"""The Anthropic adapter, driven by the SDK's own tool runner against a scripted Claude."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from anthropic import beta_async_tool, beta_tool
from anthropic.types import TextBlock, ToolUseBlock

from adapter_support import REFUND, SPECS, SQL
from arbitr.core.spec import ToolSpec
from arbitr.integrations.anthropic import (
    GuardedAsyncTool,
    GuardedTool,
    atool_results,
    guard_tool,
    guard_tools,
    tool_results,
)
from arbitr.testing.anthropic import ScriptedClaude

if TYPE_CHECKING:
    from bench.fakes.payments import FakePayments

    from arbitr.executor import Ledger

MODEL = "claude-opus-5-5"


def make_tools(payments: FakePayments, ran: list[str]) -> list[object]:
    @beta_tool
    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        """Refund an order.

        Args:
            order_id: The order to refund.
            amount: How much to refund.
        """
        made = payments.refund(order_id, amount, idempotency_key=idempotency_key)
        return f"refunded {made['refund_id']}"

    @beta_tool
    def run_sql(sql: str) -> str:
        """Run a SQL statement."""
        ran.append(sql)
        return "ok"

    return [refund, run_sql]


def run(client: object, tools: list[object], prompt: str) -> list[object]:
    runner = client.beta.messages.tool_runner(  # type: ignore[attr-defined]
        model=MODEL, max_tokens=1024, tools=tools,
        messages=[{"role": "user", "content": prompt}],
    )  # fmt: skip
    return list(runner)


def test_tool_runner_runs_allowed_calls_once_and_blocks_the_rest(
    ledger: Ledger, payments: FakePayments
) -> None:
    ran: list[str] = []
    claude = ScriptedClaude([
        [("refund", {"order_id": "o-1", "amount": 25})],
        [("refund", {"order_id": "o-1", "amount": 25})],  # the model retries
        [("run_sql", {"sql": "DROP TABLE customers"})],
        [("refund", {"order_id": "o-2", "amount": 500})],
        "All done.",
    ])  # fmt: skip
    tools = guard_tools(ledger, make_tools(payments, ran), SPECS)

    with ledger.run(principal="alice", agent_id="support-bot"):
        messages = run(claude.client(), tools, "Refund o-1 and clean up.")

    results = claude.tool_results()
    assert [r.get("is_error", False) for r in results] == [False, False, True, True]
    assert results[0]["content"] == results[1]["content"] == "refunded re_000001"
    assert "Blocked by policy 'no-destructive-sql'" in str(results[2]["content"])
    assert "needs human approval" in str(results[3]["content"])
    assert payments.count() == 1  # the retry did not refund again
    assert ran == []  # DROP TABLE never reached the database
    assert messages[-1].content[0].text == "All done."  # type: ignore[attr-defined]


def test_the_model_never_sees_or_sets_injected_parameters(
    ledger: Ledger, payments: FakePayments
) -> None:
    tools = guard_tools(ledger, make_tools(payments, []), SPECS)
    schema = tools[0].to_dict()["input_schema"]  # type: ignore[typeddict-item]
    assert "idempotency_key" not in schema["properties"]
    assert set(schema["properties"]) == {"order_id", "amount"}

    claude = ScriptedClaude([
        [("refund", {"order_id": "o-9", "amount": 5, "idempotency_key": "model-chosen"})],
        [("refund", {"order_id": "o-9", "amount": 5, "idempotency_key": "another-one"})],
    ])  # fmt: skip
    with ledger.run(principal="alice", agent_id="support-bot"):
        run(claude.client(), tools, "Refund o-9.")

    assert payments.count() == 1  # a model-chosen key cannot turn a retry into a new refund
    assert payments.find_refund("o-9", "model-chosen") is None


def test_async_tool_runner(ledger: Ledger) -> None:
    ran: list[str] = []

    @beta_async_tool
    async def run_sql(sql: str) -> str:
        """Run a SQL statement."""
        ran.append(sql)
        return "3 rows"

    tool = guard_tool(ledger, SQL, run_sql)
    assert isinstance(tool, GuardedAsyncTool)
    claude = ScriptedClaude(
        [[("run_sql", {"sql": "SELECT 1"})], [("run_sql", {"sql": "DROP TABLE t"})]]
    )

    async def main() -> None:
        with ledger.run(principal="alice", agent_id="bot"):
            runner = claude.async_client().beta.messages.tool_runner(
                model=MODEL, max_tokens=1024, tools=[tool],
                messages=[{"role": "user", "content": "go"}],
            )  # fmt: skip
            async for _ in runner:
                pass

    asyncio.run(main())
    results = claude.tool_results()
    assert results[0]["content"] == "3 rows"
    assert results[1]["is_error"] is True
    assert ran == ["SELECT 1"]


def test_tool_results_for_a_manual_loop(ledger: Ledger, payments: FakePayments) -> None:
    tools = guard_tools(ledger, make_tools(payments, []), SPECS)
    content = [
        TextBlock(type="text", text="Let me do that."),
        ToolUseBlock(type="tool_use", id="toolu_1", name="refund",
                     input={"order_id": "o-5", "amount": 10}),
        {"type": "tool_use", "id": "toolu_2", "name": "run_sql", "input": {"sql": "DROP TABLE x"}},
        {"type": "tool_use", "id": "toolu_3", "name": "not_a_tool", "input": {}},
        {"type": "tool_use", "id": "toolu_4", "name": "refund", "input": "not json"},
    ]  # fmt: skip
    with ledger.run(principal="alice", agent_id="bot"):
        results = tool_results(content, [t for t in tools if isinstance(t, GuardedTool)])

    assert [r["tool_use_id"] for r in results] == ["toolu_1", "toolu_2", "toolu_3", "toolu_4"]
    assert results[0] == {"type": "tool_result", "tool_use_id": "toolu_1",
                          "content": "refunded re_000001"}  # fmt: skip
    assert results[1]["is_error"] is True
    assert "no-destructive-sql" in str(results[1]["content"])
    assert "There is no tool named 'not_a_tool'" in str(results[2]["content"])
    assert "valid JSON" in str(results[3]["content"])


def test_tool_errors_become_error_results(ledger: Ledger) -> None:
    @beta_tool
    def flaky(order_id: str) -> str:
        """Fails."""
        raise ValueError(f"order {order_id} not found")

    tool = guard_tool(ledger, ToolSpec(name="orders.lookup", effect="read"), flaky)
    use = [{"type": "tool_use", "id": "t1", "name": "flaky", "input": {"order_id": "o-7"}}]
    with ledger.run(principal="alice", agent_id="bot"):
        results = tool_results(use, [tool])  # type: ignore[list-item]

    assert results[0]["is_error"] is True
    assert "order o-7 not found" in str(results[0]["content"])


def test_atool_results_mixes_sync_and_async_tools(ledger: Ledger, payments: FakePayments) -> None:
    @beta_async_tool
    async def lookup(order_id: str) -> str:
        """Look up an order."""
        return f"order {order_id}"

    tools = [
        *guard_tools(ledger, make_tools(payments, []), SPECS),
        guard_tool(ledger, ToolSpec(name="orders.lookup", effect="read"), lookup),
    ]
    use = [
        {"type": "tool_use", "id": "a", "name": "lookup", "input": {"order_id": "o-8"}},
        {
            "type": "tool_use",
            "id": "b",
            "name": "refund",
            "input": {"order_id": "o-8", "amount": 900},
        },
        {"type": "tool_use", "id": "c", "name": "missing", "input": {}},
    ]

    async def main() -> list[object]:
        with ledger.run(principal="alice", agent_id="bot"):
            return await atool_results(use, tools)  # type: ignore[return-value]

    results = asyncio.run(main())
    assert results[0] == {"type": "tool_result", "tool_use_id": "a", "content": "order o-8"}
    assert results[1]["is_error"] is True  # type: ignore[index]
    assert results[2]["is_error"] is True  # type: ignore[index]


def test_guard_tool_refuses_other_objects(ledger: Ledger) -> None:
    with pytest.raises(TypeError, match="beta_tool"):
        guard_tool(ledger, REFUND, object())  # type: ignore[arg-type]


def test_tools_that_cannot_take_injected_values_are_refused(ledger: Ledger) -> None:
    @beta_tool
    def refund(order_id: str, amount: float) -> str:
        """Refund an order."""
        return order_id

    with pytest.raises(TypeError, match="idempotency_key parameter"):
        guard_tool(ledger, REFUND, refund)
    creds = ToolSpec(name="crm.update", effect="write", credentials=("crm",))
    with pytest.raises(TypeError, match="credentials parameter"):
        guard_tool(ledger, creds, refund)


def test_without_a_run_the_runner_reports_it_and_runs_nothing(payments: FakePayments) -> None:
    import tempfile  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from adapter_support import KEY, POLICY  # noqa: PLC0415
    from arbitr.executor import Ledger as LedgerType  # noqa: PLC0415

    ran: list[str] = []
    with (
        tempfile.TemporaryDirectory() as folder,
        LedgerType.open(Path(folder) / "l.db", POLICY, key=KEY) as led,
    ):
        tools = guard_tools(led, make_tools(payments, ran), SPECS)
        claude = ScriptedClaude([[("run_sql", {"sql": "SELECT 1"})], "ok"])
        run(claude.client(), tools, "go")  # no ledger.run around it
    (result,) = claude.tool_results()
    assert result["is_error"] is True
    assert "ledger.run" in str(result["content"])
    assert ran == []


def test_tool_results_without_a_run_raises(ledger: Ledger, payments: FakePayments) -> None:
    from arbitr.core.errors import RunContextError  # noqa: PLC0415

    tools = guard_tools(ledger, make_tools(payments, []), SPECS)
    use = [{"type": "tool_use", "id": "t1", "name": "run_sql", "input": {"sql": "SELECT 1"}}]
    with pytest.raises(RunContextError):
        tool_results(use, [t for t in tools if isinstance(t, GuardedTool)])


def test_results_that_are_not_text_reach_claude_as_json(ledger: Ledger) -> None:
    @beta_tool
    def lookup(order_id: str) -> dict:  # type: ignore[type-arg]
        """Look up an order."""
        return {"order_id": order_id, "status": "shipped"}

    tool = guard_tool(ledger, ToolSpec(name="orders.lookup", effect="read"), lookup)
    use = [{"type": "tool_use", "id": "t1", "name": "lookup", "input": {"order_id": "o-8"}}]
    with ledger.run(principal="alice", agent_id="bot"):
        first = tool_results(use, [tool])  # type: ignore[list-item]
        again = tool_results(use, [tool])  # type: ignore[list-item]
    assert first[0]["content"] == again[0]["content"] == '{"order_id": "o-8", "status": "shipped"}'
