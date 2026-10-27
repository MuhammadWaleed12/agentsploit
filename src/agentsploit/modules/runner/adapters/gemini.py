"""GeminiAdapter: drives Google's Gemini API with native function calling."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.trace import RunTrace, ToolCall

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.runner.watcher import StreamWatcher


class GeminiAdapter(AgentAdapter):
    """Drive Gemini until it stops calling tools or reaches ``max_turns``."""

    async def run(
        self,
        config: RunnerConfig,
        payload: str,
        *,
        watcher: StreamWatcher | None = None,
    ) -> RunTrace:
        trace = RunTrace(
            provider="gemini",
            model=config.model,
            system_prompt=config.system_prompt,
        )
        trace.add_user(config.trigger_prompt)

        try:
            api_key = config.resolve_api_key()
        except ValueError as e:
            trace.error = str(e)
            trace.finished_at = datetime.now(UTC)
            return trace

        try:
            from google import genai
        except ImportError as e:  # pragma: no cover
            trace.error = f"Google Gen AI SDK not installed: {e}"
            trace.finished_at = datetime.now(UTC)
            return trace

        client = genai.Client(
            api_key=api_key,
            http_options={"timeout": int(config.timeout_seconds * 1000)},
        )
        models: Any = client.aio.models
        tools = [
            {
                "function_declarations": [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters_json_schema": tool.input_schema
                        or {"type": "object", "properties": {}},
                    }
                ]
            }
            for tool in config.mock_tools
        ]
        generation_config: dict[str, Any] = {
            "tools": tools,
            "automatic_function_calling": {"disable": True},
            "thinking_config": {"include_thoughts": True},
        }
        if config.system_prompt:
            generation_config["system_instruction"] = config.system_prompt

        contents = self._initial_contents(config)
        use_stream = bool(watcher is not None and config.stream)

        try:
            for _ in range(config.max_turns):
                if use_stream:
                    assert watcher is not None
                    (
                        aborted,
                        text,
                        thinking,
                        tool_calls,
                        model_content,
                    ) = await self._stream_one_turn(
                        client.aio, config.model, contents, generation_config, watcher
                    )
                else:
                    response = await models.generate_content(
                        model=config.model,
                        contents=contents,
                        config=generation_config,
                    )
                    aborted = False
                    text, thinking, tool_calls, model_content = self._parse_response(response)

                trace.add_assistant(text=text, thinking=thinking, tool_calls=tool_calls)
                if aborted:
                    trace.terminated_at_canary = True
                    break
                if not tool_calls:
                    break

                contents.append(model_content)
                response_parts: list[dict[str, Any]] = []
                for call in tool_calls:
                    matched = next((t for t in config.mock_tools if t.name == call.name), None)
                    tool_output = (
                        matched.render_response(payload, call.arguments)
                        if matched
                        else f"[runner] tool {call.name!r} not registered"
                    )
                    trace.add_tool_result(call.id, tool_output)
                    response_parts.append(
                        {
                            "function_response": {
                                "id": call.id,
                                "name": call.name,
                                "response": {"result": tool_output},
                            }
                        }
                    )
                contents.append({"role": "tool", "parts": response_parts})
        except Exception as e:
            trace.error = f"Gemini API error: {e}"
        finally:
            await client.aio.aclose()

        trace.finished_at = datetime.now(UTC)
        return trace

    @staticmethod
    def _initial_contents(config: RunnerConfig) -> list[dict[str, Any]]:
        contents: list[dict[str, Any]] = []
        for message in config.prepopulated_history:
            role = message.get("role")
            if role == "system":
                continue
            gemini_role = "model" if role == "assistant" else "user"
            contents.append(
                {
                    "role": gemini_role,
                    "parts": [{"text": str(message.get("content", ""))}],
                }
            )
        contents.append({"role": "user", "parts": [{"text": config.trigger_prompt}]})
        return contents

    @classmethod
    def _parse_response(cls, response: Any) -> tuple[str, str, list[ToolCall], dict[str, Any]]:
        candidates = getattr(response, "candidates", None) or []
        if not candidates:
            return "", "", [], {"role": "model", "parts": []}
        content = candidates[0].content
        raw_parts = getattr(content, "parts", None) or []
        model_content = cls._as_dict(content)
        text, thinking, tool_calls = cls._parse_parts(raw_parts)
        return text, thinking, tool_calls, model_content

    @classmethod
    def _parse_parts(cls, raw_parts: list[Any]) -> tuple[str, str, list[ToolCall]]:
        text_parts: list[str] = []
        thinking_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for index, raw_part in enumerate(raw_parts):
            part = cls._as_dict(raw_part)
            text = part.get("text")
            if text:
                (thinking_parts if part.get("thought") else text_parts).append(str(text))
            function_call = part.get("function_call")
            if not function_call:
                continue
            arguments = function_call.get("args") or {}
            if not isinstance(arguments, dict):
                arguments = {"_raw": str(arguments)}
            tool_calls.append(
                ToolCall(
                    id=str(function_call.get("id") or f"call_{index}"),
                    name=str(function_call.get("name") or ""),
                    arguments=arguments,
                )
            )
        return "".join(text_parts), "".join(thinking_parts), tool_calls

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if hasattr(value, "model_dump"):
            dumped: Any = value.model_dump(exclude_none=True)
            return dumped if isinstance(dumped, dict) else {}
        return {}

    @classmethod
    async def _stream_one_turn(
        cls,
        async_client: Any,
        model: str,
        contents: list[dict[str, Any]],
        generation_config: dict[str, Any],
        watcher: StreamWatcher,
    ) -> tuple[bool, str, str, list[ToolCall], dict[str, Any]]:
        text_parts: list[str] = []
        thinking_parts: list[str] = []
        model_parts: list[dict[str, Any]] = []
        tool_calls: list[ToolCall] = []
        aborted = False

        stream = await async_client.models.generate_content_stream(
            model=model,
            contents=contents,
            config=generation_config,
        )
        async for chunk in stream:
            candidates = getattr(chunk, "candidates", None) or []
            if not candidates:
                continue
            raw_parts = getattr(candidates[0].content, "parts", None) or []
            for index, raw_part in enumerate(raw_parts):
                part = cls._as_dict(raw_part)
                model_parts.append(part)
                delta = part.get("text")
                if delta:
                    delta = str(delta)
                    if part.get("thought"):
                        thinking_parts.append(delta)
                        aborted = watcher.feed_thinking(delta)
                    else:
                        text_parts.append(delta)
                        aborted = watcher.feed_text(delta)
                function_call = part.get("function_call")
                if function_call:
                    arguments = function_call.get("args") or {}
                    if not isinstance(arguments, dict):
                        arguments = {"_raw": str(arguments)}
                    call = ToolCall(
                        id=str(function_call.get("id") or f"call_{len(tool_calls) + index}"),
                        name=str(function_call.get("name") or ""),
                        arguments=arguments,
                    )
                    tool_calls.append(call)
                    args_delta = json.dumps(arguments, separators=(",", ":"))
                    aborted = watcher.feed_tool_call_args(call.name, args_delta) or aborted
                if aborted:
                    break
            if aborted:
                break

        return (
            aborted,
            "".join(text_parts),
            "".join(thinking_parts),
            tool_calls,
            {"role": "model", "parts": model_parts},
        )
