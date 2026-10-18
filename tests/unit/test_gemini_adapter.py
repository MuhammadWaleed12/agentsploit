"""GeminiAdapter unit tests with a deterministic in-process SDK fake."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from agentsploit.modules.runner.adapters import get_adapter
from agentsploit.modules.runner.adapters.gemini import GeminiAdapter
from agentsploit.modules.runner.config import RunnerConfig
from agentsploit.modules.runner.detector import CanarySurface
from agentsploit.modules.runner.tools import MockTool
from agentsploit.modules.runner.watcher import CanaryStreamWatcher


def _config(*, stream: bool = False) -> RunnerConfig:
    return RunnerConfig(
        provider="gemini",
        model="gemini-2.5-flash",
        api_key_env="GEMINI_API_KEY",
        trigger_prompt="please read x",
        stream=stream,
        mock_tools=[
            MockTool(
                name="read_document",
                description="reads docs",
                returns_payload=True,
                input_schema={
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            ),
        ],
    )


def test_registered_as_gemini_provider() -> None:
    assert isinstance(get_adapter("gemini"), GeminiAdapter)


class _FakeModels:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = responses
        self.requests: list[dict[str, Any]] = []

    async def generate_content(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        return self.responses.pop(0)

    async def generate_content_stream(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        chunks = self.responses.pop(0)

        async def _iterate() -> Any:
            for chunk in chunks:
                yield chunk

        return _iterate()


class _FakeAsyncClient:
    def __init__(self, responses: list[Any]) -> None:
        self.models = _FakeModels(responses)
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class _FakeClient:
    responses: ClassVar[list[Any]] = []
    last: ClassVar[_FakeClient | None] = None

    def __init__(self, **_: Any) -> None:
        self.aio = _FakeAsyncClient(self.responses.copy())
        type(self).last = self


def _response(*parts: dict[str, Any]) -> Any:
    wrapped = [SimpleNamespace(model_dump=lambda exclude_none, p=p: p) for p in parts]
    content = SimpleNamespace(
        parts=wrapped,
        model_dump=lambda exclude_none: {"role": "model", "parts": list(parts)},
    )
    return SimpleNamespace(candidates=[SimpleNamespace(content=content)])


async def test_missing_api_key_recorded_as_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    trace = await GeminiAdapter().run(_config(), "payload")
    assert trace.error is not None
    assert "not set" in trace.error


@pytest.mark.asyncio
async def test_full_tool_loop_surfaces_all_canary_channels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
    from google import genai

    _FakeClient.responses = [
        _response(
            {"text": "considering the document", "thought": True},
            {
                "function_call": {
                    "id": "call-1",
                    "name": "read_document",
                    "args": {"name": "x.pdf"},
                }
            },
        ),
        _response({"text": "final canary text"}),
    ]
    monkeypatch.setattr(genai, "Client", _FakeClient)

    trace = await GeminiAdapter().run(_config(), "payload-canary")

    assert trace.error is None, trace.error
    assert trace.messages[0].content == "please read x"
    assert trace.messages[1].thinking == "considering the document"
    assert trace.messages[1].tool_calls[0].arguments == {"name": "x.pdf"}
    assert trace.messages[2].text == "final canary text"
    assert trace.tool_results[0].content == "payload-canary"
    assert _FakeClient.last is not None
    assert _FakeClient.last.aio.closed is True
    requests = _FakeClient.last.aio.models.requests
    assert len(requests) == 2
    assert requests[0]["config"]["thinking_config"]["include_thoughts"] is True
    assert requests[1]["contents"][-1]["role"] == "tool"


@pytest.mark.asyncio
async def test_stream_aborts_before_invoking_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
    from google import genai

    _FakeClient.responses = [
        [
            _response({"text": "reasoning ", "thought": True}),
            _response(
                {
                    "function_call": {
                        "name": "read_document",
                        "args": {"name": "CANARY.txt"},
                    }
                }
            ),
        ]
    ]
    monkeypatch.setattr(genai, "Client", _FakeClient)
    watcher = CanaryStreamWatcher("CANARY")

    trace = await GeminiAdapter().run(_config(stream=True), "payload", watcher=watcher)

    assert trace.error is None, trace.error
    assert trace.terminated_at_canary is True
    assert watcher.first_surface is CanarySurface.TOOL_CALL_ARGS
    assert trace.tool_results == []
