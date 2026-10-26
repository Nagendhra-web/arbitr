"""Property tests: whatever a server lists and a client sends, only pinned tools run."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import anyio
import mcp_types as types
from fake_upstream import Upstream
from harness import connected
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from arbitr.executor import Ledger
from arbitr.integrations.mcp_proxy import McpProxy
from arbitr.integrations.mcp_specs import ServerSettings, spec_for_tool
from arbitr.policy.schema import load_policy

POLICY = load_policy(
    "version: 1\ndefault: { read: allow, write: allow, external_comm: allow, destructive: allow }\n"
)
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint", "title", "other")
hint_values = st.one_of(st.booleans(), st.none(), st.text(max_size=5), st.integers())
json_values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(-(2**53), 2**53), st.text(max_size=20)),
    lambda inner: (
        st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=8), inner, max_size=3)
    ),
    max_leaves=10,
)
names = st.sampled_from(["add", "send_email", "drop_table", "refund", "flaky", "nope", "x y"])


@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])  # cold CI containers
@given(st.dictionaries(st.sampled_from(HINTS), hint_values), st.booleans())
def test_hints_never_loosen_an_untrusted_tool(annotations: dict[str, Any], trusted: bool) -> None:
    spec = spec_for_tool("calc", "tool", annotations, ServerSettings(trust_annotations=trusted))
    if annotations.get("destructiveHint") is True:
        assert spec.effect == "destructive"
    elif annotations.get("openWorldHint") is True:
        assert spec.effect == "external_comm"
    if not trusted:
        assert spec.effect != "read"
        assert spec.untrusted_output
        assert spec.idempotency == "none"


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    descriptions=st.dictionaries(names, st.text(max_size=40), min_size=1, max_size=5),
    pinned=st.sets(names),
    calls=st.lists(st.tuples(names, st.dictionaries(st.text(max_size=8), json_values, max_size=3)),
                   max_size=6),
    on_tool_change=st.sampled_from(["deny", "require_approval"]),
)  # fmt: skip
def test_only_pinned_tools_reach_the_server(
    descriptions: dict[str, str],
    pinned: set[str],
    calls: list[tuple[str, dict[str, Any]]],
    on_tool_change: str,
) -> None:
    upstream = Upstream(descriptions=dict(descriptions), flaky_failures=0)
    accepted = {t.name for t in upstream.tools() if t.name in pinned}

    async def scenario(ledger: Ledger) -> list[types.CallToolResult]:
        for tool in upstream.tools():
            if tool.name in accepted:
                definition = tool.model_dump(by_alias=True, mode="json", exclude_none=True)
                ledger.see_tool("calc", tool.name, definition)
                ledger.accept_tool("calc", tool.name, accepted_by="test")
        async with connected(upstream.server()) as session:
            proxy = McpProxy(ledger, "calc", principal="alice", on_tool_change=on_tool_change)  # type: ignore[arg-type]
            async with connected(proxy.server(session)) as client:
                listed = {t.name for t in (await client.list_tools()).tools}
                assert listed == accepted
                return [await client.call_tool(name, args) for name, args in calls]

    with tempfile.TemporaryDirectory() as folder:
        ledger = Ledger.open(Path(folder) / "l.db", POLICY, key=b"mcp-proxy-props!" * 2)
        with ledger:
            results = anyio.run(scenario, ledger)
            assert ledger.verify().ok
    assert {name for name, _ in upstream.calls} <= accepted
    for (name, _), result in zip(calls, results, strict=True):
        if name not in accepted:
            assert result.is_error
