"""MCP annotations to ToolSpecs: hints that tighten always count, loosening needs trust."""

from __future__ import annotations

import pytest

from arbitr.core.errors import IntentError
from arbitr.integrations.mcp_specs import ServerSettings, mcp_tool_name, spec_for_tool


def spec(annotations: dict[str, object] | None, **settings: object) -> object:
    return spec_for_tool("calc", "add", annotations, ServerSettings(**settings))  # type: ignore[arg-type]


def test_names_are_namespaced_by_server() -> None:
    assert mcp_tool_name("calc", "add") == "mcp:calc/add"
    assert spec(None).name == "mcp:calc/add"  # type: ignore[attr-defined]


def test_without_annotations_a_tool_is_a_write_with_untrusted_output() -> None:
    s = spec(None)
    assert (s.effect, s.idempotency, s.untrusted_output) == ("write", "none", True)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("annotations", "effect"),
    [
        ({"destructiveHint": True}, "destructive"),
        ({"openWorldHint": True}, "external_comm"),
        ({"destructiveHint": True, "openWorldHint": True}, "destructive"),
        ({"readOnlyHint": True}, "write"),  # untrusted: a lying server cannot make itself a read
        ({"readOnlyHint": True, "destructiveHint": True}, "destructive"),
        ({"destructiveHint": False}, "write"),
    ],
)
def test_untrusted_hints_only_ever_tighten(annotations: dict[str, object], effect: str) -> None:
    assert spec(annotations).effect == effect  # type: ignore[attr-defined]


def test_idempotent_hint_needs_trust() -> None:
    assert spec({"idempotentHint": True}).idempotency == "none"  # type: ignore[attr-defined]
    trusted = spec({"idempotentHint": True}, trust_annotations=True)
    assert trusted.idempotency == "native"  # type: ignore[attr-defined]


def test_trusted_hints_can_loosen() -> None:
    read = spec({"readOnlyHint": True, "openWorldHint": False}, trust_annotations=True)
    assert (read.effect, read.untrusted_output) == ("read", False)  # type: ignore[attr-defined]


def test_tightening_hints_count_even_when_trusted() -> None:
    # Contradictory hints resolve to the stricter one.
    both = spec({"readOnlyHint": True, "destructiveHint": True}, trust_annotations=True)
    assert both.effect == "destructive"  # type: ignore[attr-defined]
    # A read of the open world (a web fetch) can carry data out in its URL, and
    # returns untrusted content.
    fetch = spec({"readOnlyHint": True, "openWorldHint": True}, trust_annotations=True)
    assert (fetch.effect, fetch.untrusted_output) == ("external_comm", True)  # type: ignore[attr-defined]


def test_the_default_effect_comes_from_settings() -> None:
    assert spec(None, default_effect="external_comm").effect == "external_comm"  # type: ignore[attr-defined]


def test_config_overrides_win_over_annotations() -> None:
    settings = {"tools": {"add": {"effect": "read", "untrusted_output": False}}}
    s = spec({"destructiveHint": True}, **settings)
    assert (s.effect, s.untrusted_output) == ("read", False)  # type: ignore[attr-defined]
    other = spec_for_tool("calc", "sub", {"destructiveHint": True}, ServerSettings(**settings))  # type: ignore[arg-type]
    assert other.effect == "destructive"


def test_bad_overrides_are_refused_when_settings_load() -> None:
    with pytest.raises(ValueError, match="effect"):
        ServerSettings(tools={"add": {"effect": "explosive"}})  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="name"):
        ServerSettings(tools={"add": {"name": "something-else"}})  # type: ignore[dict-item]


def test_non_boolean_hints_are_ignored() -> None:
    assert (
        spec({"destructiveHint": "yes", "readOnlyHint": 1}, trust_annotations=True).effect
        == "write"
    )  # type: ignore[attr-defined]


def test_tool_names_the_ledger_cannot_store_are_refused() -> None:
    with pytest.raises(IntentError, match="tool name"):
        spec_for_tool("calc", "add tool\n", None, ServerSettings())
