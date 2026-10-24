"""Tests for the static MCP tool-definition survey module."""

from __future__ import annotations

import ast
from pathlib import Path

from agentsploit.modules.survey import run_survey
from agentsploit.modules.survey.classifier import classify
from agentsploit.modules.survey.extractor import extract_tools_from_path, extract_tools_from_tree

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable_mcp"


def _tools(src: str) -> dict[str, str]:
    """Extract {name: description} from a source snippet."""
    tree = ast.parse(src)
    return {t.name: t.description for t in extract_tools_from_tree(tree, "x.py")}


def test_extract_tool_literal() -> None:
    src = """
from mcp.types import Tool
TOOLS = [Tool(name="read", description="reads a file", inputSchema={"type": "object"})]
"""
    assert _tools(src) == {"read": "reads a file"}


def test_extract_decorator_uses_docstring() -> None:
    src = '''
@mcp.tool()
def summarize(url: str) -> str:
    """Summarize a web page."""
    ...
'''
    assert _tools(src) == {"summarize": "Summarize a web page."}


def test_extract_resolves_same_file_str_enum() -> None:
    src = """
from enum import Enum
class GitTools(str, Enum):
    STATUS = "git_status"
T = Tool(name=GitTools.STATUS, description="shows status")
"""
    assert "git_status" in _tools(src)


def test_extract_from_function_factory() -> None:
    src = """
mcp.add_tool(Tool.from_function(list_databases, name="list_databases", description="list dbs"))
"""
    assert _tools(src) == {"list_databases": "list dbs"}


def test_extract_programmatic_tool_call() -> None:
    src = """
self.tool(find_foo, name="qdrant-find", description="search")
"""
    assert _tools(src) == {"qdrant-find": "search"}


def test_decorator_call_is_not_mistaken_for_registration() -> None:
    # A bare @mcp.tool() decorator has no positional arg, so Pattern D must skip it
    # and Pattern B must own it (exactly one tool, named after the function).
    src = '''
@mcp.tool()
def only_once(q: str) -> str:
    """One tool."""
    ...
'''
    assert _tools(src) == {"only_once": "One tool."}


def test_classify_source_and_sink() -> None:
    source = classify({"name": "read_doc", "inputSchema": {"properties": {"url": {}}}})
    assert source.source and not source.sink

    sink = classify({"name": "run_query", "inputSchema": {"properties": {"query": {}}}})
    assert sink.sink

    both = classify(
        {"name": "fetch_and_run", "inputSchema": {"properties": {"url": {}, "sql": {}}}}
    )
    assert both.source and both.sink


def test_classify_token_match_avoids_substring_false_positive() -> None:
    # "profile" must not match the "file" source arg signal.
    cap = classify({"name": "get_profile", "inputSchema": {"properties": {"profile_name": {}}}})
    assert not cap.source


def test_classify_return_value_content_source() -> None:
    # Read tools that return user-authored content are sources even when they only
    # take an id (they return whatever a commenter/customer wrote).
    for name in ("get_issue", "list_comments", "get_messages", "search_reviews"):
        cap = classify({"name": name, "inputSchema": {"properties": {"id": {}}}})
        assert cap.source, name
        assert any(w.startswith("content~") for w in cap.source_why), name

    # Writes and actions on the same nouns are NOT content sources.
    for name in ("create_comment", "pin_message", "delete_issue", "send_message"):
        cap = classify({"name": name, "inputSchema": {"properties": {"id": {}}}})
        assert not any(w.startswith("content~") for w in cap.source_why), name


def test_fixture_extracts_four_tools() -> None:
    tools, errors = extract_tools_from_path(FIXTURE)
    assert {t.name for t in tools} == {
        "read_secret_file",
        "read_file",
        "run_command",
        "safe_add",
    }
    assert not errors


def test_run_survey_on_fixture() -> None:
    result = run_survey(FIXTURE)
    assert len(result.tools) == 4
    assert result.findings, "expected the vulnerable fixture to produce findings"

    by_check: dict[str, set[str]] = {}
    for f in result.findings:
        by_check.setdefault(f.check, set()).add(f.target_item)

    assert any("read_secret_file" in item for item in by_check.get("tool_poisoning", set()))
    assert by_check.get("prompt_disclosure")
    assert any("run_command" in item for item in by_check.get("unsafe_tool_args", set()))

    # safe_add is a clean control and must not trip anything.
    assert not any("safe_add" in item for items in by_check.values() for item in items)


def test_run_survey_check_filter() -> None:
    result = run_survey(FIXTURE, check_filter=["tool_poisoning"])
    assert {f.check for f in result.findings} == {"tool_poisoning"}


def test_survey_result_to_dict_is_json_shaped() -> None:
    result = run_survey(FIXTURE)
    d = result.to_dict()
    assert d["summary"]["tools"] == 4
    assert "findings" in d and "capabilities" in d and "tools" in d
