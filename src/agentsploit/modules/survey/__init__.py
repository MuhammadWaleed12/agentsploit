"""Static MCP tool-definition survey.

Reads tool definitions from a local MCP server's Python source (no network, no
execution), runs AgentSploit's inventory checks over them, and labels each tool
by source/sink capability.
"""

from __future__ import annotations

from agentsploit.modules.survey.classifier import Capability, classify
from agentsploit.modules.survey.extractor import ExtractedTool, extract_tools_from_path
from agentsploit.modules.survey.surveyor import SurveyFinding, SurveyResult, run_survey

__all__ = [
    "Capability",
    "ExtractedTool",
    "SurveyFinding",
    "SurveyResult",
    "classify",
    "extract_tools_from_path",
    "run_survey",
]
