"""Tool specifications and resource references.

A ``ToolSpec`` says what a tool does to the world: its effect class, whether it
can be undone, and how Arbitr can make it safe to retry. Every tool an agent
calls has one. Tools nobody registered get ``default_tool_spec``, which assumes
a write, so nothing slips through unclassified.

Example:
    >>> spec = ToolSpec(name="payments.refund", effect="financial", idempotency="native")
    >>> spec.effect, spec.reversible
    ('financial', False)
"""

from __future__ import annotations

import re
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Effect = Literal["read", "write", "destructive", "external_comm", "financial"]
Idempotency = Literal["native", "probe", "none"]

EFFECT_RANK: Final[dict[str, int]] = {
    "read": 0,
    "write": 1,
    "external_comm": 2,
    "financial": 3,
    "destructive": 4,
}
"""Severity order. Resource extractors may raise an effect, never lower it."""

_DOTTED_PATH = re.compile(r"^[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)*:[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)*$")
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,199}$")


class ToolSpec(BaseModel):
    """How a tool affects the world and how to make calling it safe.

    Dotted paths (``resource_extractor``, ``probe``, ``compensate``, ``preview``)
    are written ``package.module:function`` and are resolved only when needed.

    Example:
        >>> ToolSpec(name="db.query", effect="read").idempotency
        'none'
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    effect: Effect
    reversible: bool = False
    idempotency: Idempotency = "none"
    idempotency_header: str | None = None
    allow_duplicates: bool = False
    untrusted_output: bool = False
    private_output: bool = False
    resource_extractor: str | None = None
    probe: str | None = None
    compensate: str | None = None
    preview: str | None = None
    """A previewer for this tool; when None, a built-in one is chosen from its resources."""
    redact: tuple[str, ...] = Field(default=())
    credentials: tuple[str, ...] = Field(default=())
    """Credentials the tool needs. Injected only at execution, after the gate allows it."""

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        if not _TOOL_NAME.match(value):
            raise ValueError(
                "tool names use letters, digits and . _ : / - and are at most 200 characters"
            )
        return value

    @field_validator("resource_extractor", "probe", "compensate", "preview")
    @classmethod
    def _check_dotted_path(cls, value: str | None) -> str | None:
        if value is not None and not _DOTTED_PATH.match(value):
            raise ValueError(f"{value!r} is not a 'package.module:function' path")
        return value

    @field_validator("redact")
    @classmethod
    def _check_redact_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for path in value:
            if not path.startswith("$"):
                raise ValueError(f"redact path {path!r} must be a JSON path starting with $")
        return value

    @model_validator(mode="after")
    def _probe_mode_needs_a_probe(self) -> ToolSpec:
        if self.idempotency == "probe" and self.probe is None:
            raise ValueError("idempotency='probe' needs a probe function")
        if self.idempotency_header is not None and self.idempotency != "native":
            raise ValueError("idempotency_header only applies when idempotency='native'")
        return self


def default_tool_spec(name: str, effect: Effect = "write") -> ToolSpec:
    """Spec for a tool nobody registered: assume it writes.

    Example:
        >>> default_tool_spec("unknown.tool").effect
        'write'
    """
    return ToolSpec(name=name, effect=effect)


def raise_effect(current: Effect, observed: Effect) -> Effect:
    """Return the more severe of two effects. Effects only ever go up.

    Example:
        >>> raise_effect("write", "destructive")
        'destructive'
        >>> raise_effect("destructive", "read")
        'destructive'
    """
    return observed if EFFECT_RANK[observed] > EFFECT_RANK[current] else current


class ResourceRef(BaseModel):
    """Something an action touches: a database, a path, a repo, a recipient.

    Example:
        >>> ResourceRef(kind="database", uri="postgres://prod/orders").kind
        'database'
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = Field(min_length=1, max_length=64)
    uri: str = Field(min_length=1, max_length=2048)
    attrs: dict[str, str] = Field(default_factory=dict)
