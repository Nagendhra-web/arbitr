"""ToolSpecs for tools an MCP server offers, from its annotations and the config.

MCP annotations (``readOnlyHint``, ``destructiveHint``, ``idempotentHint``,
``openWorldHint``) are hints written by the server, and a server can lie. So
hints that make a tool stricter always count: a destructive hint makes it
destructive, an open-world hint makes it an outbound action. Hints that would
loosen it (read-only, idempotent, a closed world) count only for a server the
config trusts. Per-tool settings in the config win over both.

Tools without annotations are writes (or the server's ``default_effect``),
and their output is untrusted, since it comes from outside Arbitr.

Example:
    >>> spec_for_tool("calc", "add", {"destructiveHint": True}, ServerSettings()).effect
    'destructive'
"""

from __future__ import annotations

from collections.abc import Mapping  # noqa: TC003 - pydantic reads it at runtime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from arbitr.core.errors import IntentError
from arbitr.core.spec import Effect, ToolSpec, raise_effect

__all__ = ["ServerSettings", "mcp_tool_name", "spec_for_tool"]

_PREFIX: Final = "mcp:"


def mcp_tool_name(server: str, tool: str) -> str:
    """The ledger's name for one server's tool: ``mcp:<server>/<tool>``.

    Example:
        >>> mcp_tool_name("calc", "add")
        'mcp:calc/add'
    """
    return f"{_PREFIX}{server}/{tool}"


class ServerSettings(BaseModel):
    """How Arbitr treats one MCP server's tools."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    trust_annotations: bool = False
    """Let this server's read-only, idempotent and closed-world hints loosen its tools."""
    default_effect: Effect = "write"
    """The effect of a tool the server gives no stricter hint for."""
    tools: Mapping[str, Mapping[str, Any]] = {}
    """Per tool, ToolSpec fields that win over the annotations (``effect``, ``idempotency``...)."""

    @field_validator("tools")
    @classmethod
    def _check_tools(
        cls, value: Mapping[str, Mapping[str, Any]]
    ) -> Mapping[str, Mapping[str, Any]]:
        for tool, fields in value.items():
            if "name" in fields:
                raise ValueError(f"tools.{tool}: the name is set by Arbitr, not the config")
            try:
                ToolSpec(**{"name": "check", "effect": "write", **fields})
            except ValidationError as exc:
                raise ValueError(
                    f"tools.{tool}: {exc.errors()[0]['loc'][0]}: {exc.errors()[0]['msg']}"
                ) from None
        return value


def spec_for_tool(
    server: str,
    tool: str,
    annotations: Mapping[str, object] | None,
    settings: ServerSettings,
) -> ToolSpec:
    """The ToolSpec for ``tool`` on ``server``.

    Raises:
        IntentError: the server and tool names do not make a valid tool name.
    """
    read_only = _hint(annotations, "readOnlyHint")
    destructive = _hint(annotations, "destructiveHint")
    open_world = _hint(annotations, "openWorldHint")
    idempotent = _hint(annotations, "idempotentHint")
    trusted = settings.trust_annotations

    effect: Effect = "read" if trusted and read_only is True else settings.default_effect
    if destructive is True:
        effect = raise_effect(effect, "destructive")
    if open_world is True:  # a fetch can carry data out in its URL
        effect = raise_effect(effect, "external_comm")
    fields: dict[str, Any] = {
        "name": mcp_tool_name(server, tool),
        "effect": effect,
        "idempotency": "native" if trusted and idempotent is True else "none",
        "untrusted_output": not (trusted and open_world is False),
    }
    fields.update(settings.tools.get(tool, {}))
    try:
        return ToolSpec(**fields)
    except ValidationError as exc:
        raise IntentError(
            f"the MCP tool {server}/{tool} cannot be used: tool name or settings are not valid"
            f" ({exc.errors()[0]['msg']})"
        ) from None


def _hint(annotations: Mapping[str, object] | None, key: str) -> bool | None:
    """A hint's value, or None when it is absent or not a boolean."""
    value = (annotations or {}).get(key)
    return value if isinstance(value, bool) else None
