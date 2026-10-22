"""Heuristic source/sink capability labels for extracted tools.

This is NOT a confirmed data-flow. It labels each tool by whether it looks like
it ingests untrusted external content (a "source") and/or performs a high-impact
action (a "sink"). A server exposing both in one context is where a source-to-
sink chain could exist, not proof that an agent will bridge them.

Tuned for precision: source names are limited to external-content verbs (no bare
get/list/search/read/open, which are mostly internal enumeration), and matching
is camelCase- and delimiter-aware token matching, so `executeQuery` -> {execute,
query} and `fileUrl` -> {file, url}, while `dsql_read_docs` does not spuriously
match `sql`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_SOURCE_NAME = ("fetch", "crawl", "scrape", "download", "browse")
_SOURCE_ARG = (
    "url",
    "uri",
    "href",
    "endpoint",
    "webpage",
    "website",
    "path",
    "file",
    "filepath",
    "filename",
    "document",
)
_SINK_NAME = (
    "exec",
    "execute",
    "run",
    "shell",
    "command",
    "eval",
    "query",
    "sql",
    "cypher",
    "gremlin",
    "write",
    "create",
    "update",
    "delete",
    "remove",
    "insert",
    "send",
    "email",
    "commit",
    "push",
    "publish",
    "upload",
    "drop",
    "alter",
)
_SINK_ARG = (
    "command",
    "cmd",
    "query",
    "sql",
    "cypher",
    "code",
    "script",
    "body",
    "payload",
    "statement",
    "expression",
)

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^A-Za-z0-9]+")


@dataclass
class Capability:
    """How a single tool is labeled, with the signals that triggered it."""

    name: str
    source: bool
    sink: bool
    source_why: list[str]
    sink_why: list[str]


def _tokens(s: str) -> set[str]:
    """camelCase- and delimiter-aware token set.

    `executeQuery` -> {execute, query}, `fileUrl` -> {file, url}, and
    `dsql_read_docs` -> {dsql, read, docs} (no spurious `sql`).
    """
    return {t for t in _SPLIT.split(_CAMEL.sub(" ", s).lower()) if t}


def classify(tool: dict[str, Any]) -> Capability:
    """Label one tool dict (name + inputSchema) as source and/or sink."""
    name = str(tool.get("name", ""))
    name_toks = _tokens(name)
    args = list((tool.get("inputSchema", {}) or {}).get("properties", {}).keys())
    src = [f"name~{k}" for k in _SOURCE_NAME if k in name_toks]
    snk = [f"name~{k}" for k in _SINK_NAME if k in name_toks]
    for a in args:
        toks = _tokens(a)
        if toks & set(_SOURCE_ARG):
            src.append(f"arg:{a}")
        if toks & set(_SINK_ARG):
            snk.append(f"arg:{a}")
    return Capability(
        name=name,
        source=bool(src),
        sink=bool(snk),
        source_why=src[:3],
        sink_why=snk[:3],
    )
