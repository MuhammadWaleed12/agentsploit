"""Run a static survey over a local MCP server checkout.

Extracts tool definitions from Python source, runs AgentSploit's transport-
agnostic inventory checks over them, and labels each tool source/sink. No
network, no execution.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from agentsploit.modules.mcp.checks import ALL_CHECKS
from agentsploit.modules.mcp.checks.base import Check
from agentsploit.modules.mcp.client import MCPInventory
from agentsploit.modules.survey.classifier import Capability, classify
from agentsploit.modules.survey.extractor import ExtractedTool, extract_tools_from_path


@dataclass
class SurveyFinding:
    check: str
    severity: str
    title: str
    target_item: str
    evidence: dict[str, Any]


@dataclass
class SurveyResult:
    root: str
    tools: list[ExtractedTool]
    findings: list[SurveyFinding]
    capabilities: list[Capability]
    parse_errors: list[str]

    @property
    def n_sources(self) -> int:
        return sum(1 for c in self.capabilities if c.source)

    @property
    def n_sinks(self) -> int:
        return sum(1 for c in self.capabilities if c.sink)

    @property
    def n_both(self) -> int:
        return sum(1 for c in self.capabilities if c.source and c.sink)

    @property
    def coexists(self) -> bool:
        return self.n_sources > 0 and self.n_sinks > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "summary": {
                "tools": len(self.tools),
                "findings": len(self.findings),
                "sources": self.n_sources,
                "sinks": self.n_sinks,
                "both": self.n_both,
                "source_sink_coexist": self.coexists,
                "parse_errors": len(self.parse_errors),
            },
            "tools": [asdict(t) for t in self.tools],
            "findings": [asdict(f) for f in self.findings],
            "capabilities": [asdict(c) for c in self.capabilities],
            "parse_errors": self.parse_errors,
        }


def _inventory_checks(check_filter: Iterable[str] | None) -> list[type[Check]]:
    checks = [c for c in ALL_CHECKS if isinstance(c, type) and issubclass(c, Check)]
    if check_filter:
        wanted = set(check_filter)
        checks = [c for c in checks if getattr(c, "NAME", None) in wanted]
    return checks


def run_survey(root: Path, check_filter: Iterable[str] | None = None) -> SurveyResult:
    """Survey a local checkout and return the extracted tools, findings, and labels."""
    tools, parse_errors = extract_tools_from_path(root)
    tool_dicts: list[dict[str, Any]] = [asdict(t) for t in tools]

    inventory = MCPInventory(tools=tool_dicts)
    findings: list[SurveyFinding] = []
    for check_cls in _inventory_checks(check_filter):
        check = check_cls()
        for result in check.run(inventory):
            severity = (
                result.severity.name if hasattr(result.severity, "name") else str(result.severity)
            )
            findings.append(
                SurveyFinding(
                    check=check.NAME,
                    severity=severity,
                    title=result.title,
                    target_item=result.target_item,
                    evidence=result.evidence_extra or {},
                )
            )

    capabilities = [classify(td) for td in tool_dicts]
    return SurveyResult(
        root=str(root),
        tools=tools,
        findings=findings,
        capabilities=capabilities,
        parse_errors=parse_errors,
    )
