"""Static extraction of MCP tool definitions from Python source.

Reads tool definitions straight from a server's source code with the `ast`
module. Nothing is imported or executed, so this is safe to run against code you
have not reviewed. It recognizes the common ways Python MCP servers declare
tools; see `extract_tools_from_path` for the supported patterns and their known
limits.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DECORATOR_TOOL_NAMES = {"tool"}  # matches @mcp.tool(), @server.tool(), @app.tool()
_ANNOTATION_TO_JSON = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
}

# Directories that never hold a server's own tool definitions.
_SKIP_DIRS = {".venv", "venv", "node_modules", "build", "dist", "tests", "test"}

EnumMap = dict[tuple[str, str], str]


@dataclass
class ExtractedTool:
    """One tool definition read from source, plus how it was found."""

    name: str
    description: str
    inputSchema: dict[str, Any] = field(default_factory=dict)  # noqa: N815 (MCP field name)
    source: str = ""  # file:line
    method: str = ""  # which pattern matched
    schema_partial: bool = False


def _build_enum_map(tree: ast.AST) -> EnumMap:
    """Map (ClassName, MEMBER) -> str value for same-file str/Enum classes.

    Handles the common `class GitTools(str, Enum): STATUS = "git_status"` pattern
    so `name=GitTools.STATUS` resolves to the real tool name.
    """
    enums: EnumMap = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = {
            (b.id if isinstance(b, ast.Name) else getattr(b, "attr", "")) for b in node.bases
        }
        if not (base_names & {"Enum", "IntEnum", "StrEnum"}):
            continue
        for stmt in node.body:
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            ):
                enums[(node.name, stmt.targets[0].id)] = stmt.value.value
    return enums


def _static_str(node: ast.expr | None, enums: EnumMap | None = None) -> str | None:
    """Constant-fold a string expression: literal, implicit concat, `"a" + "b"`,
    or a same-file `str`-Enum member. None if it isn't statically a string.
    """
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _static_str(node.left, enums), _static_str(node.right, enums)
        if left is not None and right is not None:
            return left + right
    if enums and isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return enums.get((node.value.id, node.attr))
    return None


def _static_obj(node: ast.expr | None) -> Any:
    """literal_eval a node (used for inputSchema dicts). None if not a literal."""
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _decorator_is_tool(dec: ast.expr) -> bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr in _DECORATOR_TOOL_NAMES
    if isinstance(target, ast.Name):
        return target.id in _DECORATOR_TOOL_NAMES
    return False


def _schema_from_signature(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    """Rough inputSchema inferred from annotated params (skips self/ctx/context)."""
    props: dict[str, Any] = {}
    required: list[str] = []
    args = fn.args
    defaults_start = len(args.args) - len(args.defaults)
    for i, a in enumerate(args.args):
        if a.arg in {"self", "cls", "ctx", "context"}:
            continue
        jtype = None
        if isinstance(a.annotation, ast.Name):
            jtype = _ANNOTATION_TO_JSON.get(a.annotation.id)
        props[a.arg] = {"type": jtype} if jtype else {}
        if i < defaults_start:
            required.append(a.arg)
    schema: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def extract_tools_from_tree(tree: ast.AST, relpath: str) -> list[ExtractedTool]:
    """Extract tool definitions from one parsed module."""
    tools: list[ExtractedTool] = []
    enums = _build_enum_map(tree)

    # Pattern A: Tool(name=..., description=..., inputSchema=...) call literals.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            fname = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
            if fname != "Tool":
                continue
            name = _static_str(_kw(node, "name"), enums)
            if name is None:
                continue
            desc = _static_str(_kw(node, "description"), enums) or ""
            schema = _static_obj(_kw(node, "inputSchema"))
            if not isinstance(schema, dict):
                schema = _static_obj(_kw(node, "input_schema"))
            partial = not isinstance(schema, dict)
            tools.append(
                ExtractedTool(
                    name=name,
                    description=desc,
                    inputSchema=schema if isinstance(schema, dict) else {},
                    source=f"{relpath}:{node.lineno}",
                    method="Tool()-literal",
                    schema_partial=partial,
                )
            )

    # Pattern B: @mcp.tool() / @server.tool() decorated functions.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool_decs = [d for d in node.decorator_list if _decorator_is_tool(d)]
            if not tool_decs:
                continue
            dec = tool_decs[0]
            dec_name = _static_str(_kw(dec, "name"), enums) if isinstance(dec, ast.Call) else None
            dec_desc = (
                _static_str(_kw(dec, "description"), enums) if isinstance(dec, ast.Call) else None
            )
            tool_name = dec_name or node.name
            tool_desc = dec_desc if dec_desc is not None else (ast.get_docstring(node) or "")
            tools.append(
                ExtractedTool(
                    name=tool_name,
                    description=tool_desc,
                    inputSchema=_schema_from_signature(node),
                    source=f"{relpath}:{node.lineno}",
                    method="@tool-decorator",
                    schema_partial=True,  # signature-derived schema is approximate
                )
            )

    # Pattern C: Tool.from_function(fn, name=..., description=...) factory calls.
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "from_function"
        ):
            name = _static_str(_kw(node, "name"), enums)
            if name is None:
                continue
            tools.append(
                ExtractedTool(
                    name=name,
                    description=_static_str(_kw(node, "description"), enums) or "",
                    inputSchema={},
                    source=f"{relpath}:{node.lineno}",
                    method="from_function()",
                    schema_partial=True,
                )
            )

    # Pattern D: programmatic registration x.tool(fn, name=...) / x.add_tool(...).
    # Requires a positional arg plus a literal name=, so it can't collide with the
    # zero-positional @x.tool() decorator (Pattern B) or a from_function argument.
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"tool", "add_tool"}
            and node.args
        ):
            first = node.args[0]
            if isinstance(first, ast.Call):  # e.g. add_tool(Tool.from_function(...))
                continue
            name = _static_str(_kw(node, "name"), enums)
            if name is None:
                continue
            tools.append(
                ExtractedTool(
                    name=name,
                    description=_static_str(_kw(node, "description"), enums) or "",
                    inputSchema={},
                    source=f"{relpath}:{node.lineno}",
                    method=f".{node.func.attr}()-call",
                    schema_partial=True,
                )
            )

    # De-dupe by (name, source).
    seen: set[tuple[str, str]] = set()
    unique: list[ExtractedTool] = []
    for t in tools:
        key = (t.name, t.source)
        if key not in seen:
            seen.add(key)
            unique.append(t)
    return unique


def extract_tools_from_path(root: Path) -> tuple[list[ExtractedTool], list[str]]:
    """Walk a checkout and extract tools from every parseable .py file.

    Returns (tools, parse_errors). Counts are a lower bound: tools declared
    through Pydantic schemas, cross-file enums, or custom (non-SDK) registry
    classes, and tools in non-Python servers, are not captured.
    """
    tools: list[ExtractedTool] = []
    parse_errors: list[str] = []
    if root.is_file():
        files = [root]
    else:
        files = sorted(root.rglob("*.py"))
    for py in files:
        rel = py.relative_to(root) if root.is_dir() else Path(py.name)
        if set(rel.parts[:-1]) & _SKIP_DIRS:
            continue
        try:
            src = py.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src, filename=str(py))
        except (SyntaxError, ValueError) as e:
            parse_errors.append(f"{rel}: {e}")
            continue
        tools.extend(extract_tools_from_tree(tree, str(rel)))
    return tools, parse_errors
