"""The gate, the ledger and the tool see the same argument values, in every adapter.

A tool's validator turns ``"42"`` into ``42``. If the gate checked the raw
``"42"``, a rule ``account eq 42`` would not match, the call would be allowed,
and the tool would then act on account 42. So each adapter validates the
model's arguments with the tool's own types before the gate.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest
from agents import Agent, Runner
from anthropic import beta_tool
from langchain_core.tools import tool

from adapter_support import KEY
from arbitr.core.spec import ToolSpec
from arbitr.executor import Ledger
from arbitr.integrations.anthropic import guard_tool, tool_results
from arbitr.integrations.langgraph import guarded_tool_node
from arbitr.integrations.openai_agents import guarded_function_tool
from arbitr.policy.schema import load_policy
from arbitr.testing.langgraph import ScriptedAgent, tool_messages
from arbitr.testing.openai_agents import ScriptedModel

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

POLICY = load_policy("""
version: 1
default: { write: allow }
rules:
  - id: frozen-account
    when: { tool: accounts.close, args: [{ path: "$.account", op: eq, value: 42 }] }
    then: deny
    reason: Account 42 is frozen.
""")
SPEC = ToolSpec(name="accounts.close", effect="write")


@pytest.fixture
def typed_ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "t.db", POLICY, key=KEY) as led:
        yield led


def stored_args(ledger: Ledger) -> list[dict[str, Any]]:
    return [json.loads(row.args_redacted) for row in ledger.find_intents(tool="accounts.close")]


def test_anthropic_checks_the_values_the_tool_gets(typed_ledger: Ledger) -> None:
    closed: list[int] = []

    @beta_tool
    def close(account: int) -> str:
        """Close an account."""
        closed.append(account)
        return "closed"

    guarded = guard_tool(typed_ledger, SPEC, close)
    uses = [
        {"type": "tool_use", "id": "a", "name": "close", "input": {"account": "42"}},
        {"type": "tool_use", "id": "b", "name": "close", "input": {"account": "lots"}},
    ]
    with typed_ledger.run(principal="alice", agent_id="bot"):
        results = tool_results(uses, [guarded])  # type: ignore[list-item]

    assert "Blocked by policy 'frozen-account'" in str(results[0]["content"])
    assert "do not fit its parameters" in str(results[1]["content"])
    assert closed == []
    assert stored_args(typed_ledger) == [{"account": 42}]  # recorded as the tool would get it


def test_openai_agents_checks_the_values_the_tool_gets(typed_ledger: Ledger) -> None:
    closed: list[int] = []

    @guarded_function_tool(typed_ledger, SPEC, strict_mode=False)
    def close(account: int) -> str:
        """Close an account."""
        closed.append(account)
        return "closed"

    model = ScriptedModel([[("close", {"account": "42"})], [("close", {"account": "lots"})]])
    with typed_ledger.run(principal="alice", agent_id="bot"):
        agent = Agent(name="bot", tools=[close])
        asyncio.run(Runner.run(agent, "go", run_config=model.run_config()))

    outputs = model.tool_outputs()
    assert outputs[0].startswith("Blocked by policy 'frozen-account'")
    assert "do not fit its parameters" in outputs[1]
    assert closed == []
    assert stored_args(typed_ledger) == [{"account": 42}]


def test_langgraph_checks_the_values_the_tool_gets(typed_ledger: Ledger) -> None:
    closed: list[int] = []

    @tool
    def close(account: int) -> str:
        """Close an account."""
        closed.append(account)
        return "closed"

    node = guarded_tool_node(typed_ledger, [close], {"close": SPEC}, principal="alice")
    agent = ScriptedAgent([[("close", {"account": "42"}), ("close", {"account": "lots"})]])
    state = agent.graph(node).invoke(
        {"messages": [("user", "go")]}, {"configurable": {"thread_id": "t-types"}}
    )

    messages = tool_messages(state)
    assert "Blocked by policy 'frozen-account'" in str(messages[0].content)
    assert "do not fit its parameters" in str(messages[1].content)
    assert closed == []
    assert stored_args(typed_ledger) == [{"account": 42}]
