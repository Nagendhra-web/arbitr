"""The LangGraph adapter: a prebuilt ToolNode with the gate in its official hooks."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Annotated, Any

import pytest
from langchain_core.messages import ToolMessage
from langchain_core.tools import InjectedToolArg, InjectedToolCallId, tool
from langgraph.types import Command

from adapter_support import KEY, POLICY, SPECS
from arbitr.core.errors import RunContextError
from arbitr.core.spec import ToolSpec
from arbitr.executor import Ledger, current_run
from arbitr.integrations.langgraph import guarded_tool_node
from arbitr.testing.langgraph import ScriptedAgent, tool_messages

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from bench.fakes.payments import FakePayments

CONFIG: Any = {"configurable": {"thread_id": "t-1"}}
SECRET = "cred-" + "value-4417"


class Creds:
    def get(self, name: str) -> str:
        return SECRET


def make_tools(payments: FakePayments, ran: list[str]) -> list[Any]:
    @tool
    def refund(
        order_id: str,
        amount: float,
        idempotency_key: Annotated[str | None, InjectedToolArg] = None,
    ) -> str:
        """Refund an order."""
        made = payments.refund(order_id, amount, idempotency_key=idempotency_key)
        return f"refunded {made['refund_id']}"

    @tool
    def run_sql(sql: str) -> str:
        """Run a SQL statement."""
        ran.append(sql)
        return "ok"

    return [refund, run_sql]


def node(ledger: Ledger, tools: list[Any], specs: Any = SPECS, **kwargs: Any) -> Any:
    kwargs.setdefault("principal", "alice")
    return guarded_tool_node(ledger, tools, specs, **kwargs)


def test_graph_runs_allowed_calls_once_and_blocks_the_rest(
    ledger: Ledger, payments: FakePayments
) -> None:
    ran: list[str] = []
    agent = ScriptedAgent([
        [("refund", {"order_id": "o-1", "amount": 25})],
        [("refund", {"order_id": "o-1", "amount": 25})],
        [("run_sql", {"sql": "DROP TABLE customers"})],
        [("refund", {"order_id": "o-2", "amount": 500})],
        "All done.",
    ])  # fmt: skip
    graph = agent.graph(node(ledger, make_tools(payments, ran)))

    state = graph.invoke({"messages": [("user", "Refund o-1")]}, CONFIG)

    messages = tool_messages(state)
    assert [m.status for m in messages] == ["success", "success", "error", "error"]
    assert messages[0].content == messages[1].content == "refunded re_000001"
    assert "Blocked by policy 'no-destructive-sql'" in str(messages[2].content)
    assert "needs human approval" in str(messages[3].content)
    assert [m.tool_call_id for m in messages] == ["call_001", "call_002", "call_003", "call_004"]
    assert payments.count() == 1
    assert ran == []
    assert state["messages"][-1].content == "All done."


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_the_tool_gets_the_ledgers_key(ledger: Ledger, mode: str) -> None:
    got: list[tuple[str | None, str]] = []

    def record(order_id: str, key: str | None) -> str:
        handle = current_run()
        got.append((key, handle.last_idempotency_key if handle else ""))
        return "ok"

    if mode == "sync":

        @tool
        def refund(
            order_id: str, idempotency_key: Annotated[str | None, InjectedToolArg] = None
        ) -> str:
            """Refund an order."""
            return record(order_id, idempotency_key)
    else:

        @tool
        async def refund(
            order_id: str, idempotency_key: Annotated[str | None, InjectedToolArg] = None
        ) -> str:
            """Refund an order."""
            return record(order_id, idempotency_key)

    agent = ScriptedAgent([[("refund", {"order_id": "o-1", "idempotency_key": "forged"})]])
    graph = agent.graph(node(ledger, [refund]))
    if mode == "sync":
        graph.invoke({"messages": [("user", "go")]}, CONFIG)
    else:
        asyncio.run(graph.ainvoke({"messages": [("user", "go")]}, CONFIG))

    ((key, expected),) = got
    assert key == expected
    assert key not in (None, "forged")


@pytest.fixture
def cred_ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "c.db", POLICY, key=KEY, credentials=Creds()) as led:
        yield led


def test_credentials_reach_the_tool_and_nothing_else(cred_ledger: Ledger) -> None:
    seen: list[object] = []

    @tool
    def crm_update(
        contact: str, credentials: Annotated[dict[str, str] | None, InjectedToolArg] = None
    ) -> str:
        """Update a CRM contact."""
        seen.append(credentials)
        return f"updated {contact} with {credentials}"  # a careless tool echoes it

    spec = ToolSpec(name="crm.update", effect="write", credentials=("crm",))
    agent = ScriptedAgent([[("crm_update", {"contact": "c-1"})]])
    state = agent.graph(node(cred_ledger, [crm_update], {"crm_update": spec})).invoke(
        {"messages": [("user", "go")]}, CONFIG
    )

    assert seen == [{"crm": SECRET}]
    assert SECRET not in str(tool_messages(state)[0].content)
    assert all(SECRET not in event.payload for event in cred_ledger.events())


def test_ambiguous_errors_end_unknown_and_are_not_retried(ledger: Ledger) -> None:
    sent: list[str] = []

    @tool
    def send_email(to: str) -> str:
        """Send an email."""
        sent.append(to)
        raise TimeoutError("the mail server accepted it, then the reply timed out")

    spec = ToolSpec(name="email.send", effect="external_comm")
    agent = ScriptedAgent([[("send_email", {"to": "a@example.com"})]] * 2)
    graph = agent.graph(node(ledger, [send_email], {"send_email": spec}, handle_tool_errors=True))
    state = graph.invoke({"messages": [("user", "go")]}, CONFIG)

    messages = tool_messages(state)
    assert all(m.status == "error" for m in messages)
    assert "may or may not have happened" in str(messages[0].content)
    assert sent == ["a@example.com"]  # the model's retry did not send it again
    (row,) = ledger.find_intents(tool="email.send")
    assert row.state.value == "UNKNOWN"


def test_handle_tool_errors_keeps_toolnode_meaning(ledger: Ledger) -> None:
    @tool
    def lookup(order_id: str) -> str:
        """Look up an order."""
        raise KeyError(order_id)

    specs = {"lookup": ToolSpec(name="orders.lookup", effect="read")}

    def on_key_error(error: KeyError) -> str:
        return f"no such order {error}"

    for flag, expected in [
        (True, "Error: KeyError('o-5')"),
        ("Lookup failed.", "Lookup failed."),
        (on_key_error, "no such order 'o-5'"),
        ((KeyError,), "Error: KeyError('o-5')"),
    ]:
        agent = ScriptedAgent([[("lookup", {"order_id": "o-5"})]])
        config = {"configurable": {"thread_id": f"t-{flag!s:.6}"}}
        graph = agent.graph(node(ledger, [lookup], specs, handle_tool_errors=flag))
        state = graph.invoke({"messages": [("user", "go")]}, config)
        assert str(tool_messages(state)[0].content).startswith(expected)

    for flag in (False, (ValueError,)):
        agent = ScriptedAgent([[("lookup", {"order_id": "o-5"})]])
        graph = agent.graph(node(ledger, [lookup], specs, handle_tool_errors=flag))
        with pytest.raises(KeyError):
            graph.invoke({"messages": [("user", "go")]}, {"configurable": {"thread_id": "t-x"}})


def test_tool_errors_are_failures_that_can_run_again(ledger: Ledger) -> None:
    attempts: list[int] = []

    @tool
    def lookup(order_id: str) -> str:
        """Look up an order."""
        attempts.append(1)
        if len(attempts) == 1:
            raise ValueError("order service said no")
        return f"order {order_id}"

    agent = ScriptedAgent([[("lookup", {"order_id": "o-5"})], [("lookup", {"order_id": "o-5"})]])
    specs = {"lookup": ToolSpec(name="orders.lookup", effect="read")}
    state = agent.graph(node(ledger, [lookup], specs, handle_tool_errors=True)).invoke(
        {"messages": [("user", "go")]}, CONFIG
    )

    messages = tool_messages(state)
    assert messages[0].status == "error"
    assert "order service said no" in str(messages[0].content)
    assert messages[1].content == "order o-5"
    assert len(attempts) == 2
    assert [row.state.value for row in ledger.find_intents(tool="orders.lookup")] == ["SUCCEEDED"]


def test_a_tool_that_answers_with_an_error_is_a_failure(ledger: Ledger) -> None:
    @tool
    def lookup(order_id: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> ToolMessage:
        """Look up an order."""
        return ToolMessage("not found", tool_call_id=tool_call_id, status="error")

    agent = ScriptedAgent([[("lookup", {"order_id": "o-6"})]])
    specs = {"lookup": ToolSpec(name="orders.lookup", effect="read")}
    state = agent.graph(node(ledger, [lookup], specs)).invoke(
        {"messages": [("user", "go")]}, CONFIG
    )
    assert tool_messages(state)[0].status == "error"
    assert [row.state.value for row in ledger.find_intents(tool="orders.lookup")] == ["FAILED"]


def test_each_thread_is_one_ledger_run(ledger: Ledger, payments: FakePayments) -> None:
    tools = make_tools(payments, [])
    for thread in ("t-a", "t-a", "t-b"):
        agent = ScriptedAgent([[("refund", {"order_id": "o-3", "amount": 5})]])
        graph = agent.graph(node(ledger, tools))
        graph.invoke({"messages": [("user", "go")]}, {"configurable": {"thread_id": thread}})

    assert payments.count() == 2  # the repeat in thread t-a returned the receipt
    ids = {run.run_id for run in ledger.runs()}
    assert ids == {"thread-langgraph-t-a", "thread-langgraph-t-b"}


def test_graphs_with_other_agents_never_share_a_run(ledger: Ledger, payments: FakePayments) -> None:
    tools = make_tools(payments, [])
    for agent_id in ("billing", "support"):
        agent = ScriptedAgent([[("refund", {"order_id": "o-4", "amount": 5})]])
        graph = agent.graph(node(ledger, tools, agent_id=agent_id))
        graph.invoke({"messages": [("user", "go")]}, CONFIG)
    assert payments.count() == 2


def test_the_principal_comes_from_the_app_never_from_client_config(
    ledger: Ledger, payments: FakePayments
) -> None:
    tools = make_tools(payments, [])
    agent = ScriptedAgent([[("run_sql", {"sql": "SELECT 1"})]])
    forged = {"configurable": {"thread_id": "t-c", "principal": "mallory"}}
    agent.graph(node(ledger, tools)).invoke({"messages": [("user", "go")]}, forged)
    record = ledger.run_record("thread-langgraph-t-c")
    assert record is not None
    assert record.principal == "alice"

    def from_auth(config: Any) -> str | None:
        return config["configurable"].get("user_id")

    agent = ScriptedAgent([[("run_sql", {"sql": "SELECT 2"})]])
    graph = agent.graph(node(ledger, tools, principal=from_auth))
    graph.invoke(
        {"messages": [("user", "go")]}, {"configurable": {"thread_id": "t-d", "user_id": "bob"}}
    )
    assert ledger.run_record("thread-langgraph-t-d").principal == "bob"  # type: ignore[union-attr]

    agent = ScriptedAgent([[("run_sql", {"sql": "SELECT 3"})]])
    graph = agent.graph(node(ledger, tools, principal=from_auth))
    with pytest.raises(RunContextError, match="another principal"):
        graph.invoke(
            {"messages": [("user", "go")]}, {"configurable": {"thread_id": "t-d", "user_id": "eve"}}
        )


def test_without_a_run_or_principal_calls_are_refused(
    ledger: Ledger, payments: FakePayments
) -> None:
    ran: list[str] = []
    for principal, config in [(None, CONFIG), ("alice", {})]:
        agent = ScriptedAgent([[("run_sql", {"sql": "SELECT 1"})]])
        graph = agent.graph(node(ledger, make_tools(payments, ran), principal=principal))
        with pytest.raises(RunContextError):
            graph.invoke({"messages": [("user", "go")]}, config)
    assert ran == []


def test_inside_ledger_run_the_graph_uses_that_run(ledger: Ledger, payments: FakePayments) -> None:
    agent = ScriptedAgent([[("run_sql", {"sql": "SELECT 1"})]])
    graph = agent.graph(node(ledger, make_tools(payments, []), principal=None))
    with ledger.run(principal="bob", agent_id="bot", run_id="outer"):
        graph.invoke({"messages": [("user", "go")]}, CONFIG)
    assert [row.run_id for row in ledger.find_intents(tool="db.execute")] == ["outer"]


def test_async_graph_with_parallel_calls(ledger: Ledger, payments: FakePayments) -> None:
    ran: list[str] = []

    @tool
    async def lookup(order_id: str) -> str:
        """Look up an order."""
        ran.append(order_id)
        return f"order {order_id}"

    same_refund = ("refund", {"order_id": "o-9", "amount": 3})
    agent = ScriptedAgent([
        [("lookup", {"order_id": "o-4"}), ("run_sql", {"sql": "DROP TABLE t"}),
         same_refund, same_refund],
        [("lookup", {"order_id": "o-4"})],
    ])  # fmt: skip
    specs = {**SPECS, "lookup": ToolSpec(name="orders.lookup", effect="read")}
    graph = agent.graph(node(ledger, [*make_tools(payments, []), lookup], specs))
    state = asyncio.run(graph.ainvoke({"messages": [("user", "go")]}, CONFIG))

    by_id = {m.tool_call_id: m for m in tool_messages(state)}
    assert by_id["call_001"].content == by_id["call_005"].content == "order o-4"
    assert by_id["call_002"].status == "error"  # DROP TABLE
    # Two identical refunds race for one lease: the winner refunds, the other
    # gets the same receipt or is told the action is already running.
    refunds = [by_id["call_003"], by_id["call_004"]]
    assert any(m.status == "success" and m.content == "refunded re_000001" for m in refunds)
    for message in refunds:
        assert message.content == "refunded re_000001" or "already running" in str(message.content)
    assert ran == ["o-4"]
    assert payments.count() == 1


def test_sync_graph_with_parallel_identical_calls(ledger: Ledger, payments: FakePayments) -> None:
    calls = [("refund", {"order_id": "o-7", "amount": 4})] * 4
    graph = ScriptedAgent([calls]).graph(node(ledger, make_tools(payments, [])))
    state = graph.invoke({"messages": [("user", "go")]}, CONFIG)
    contents = {str(m.content) for m in tool_messages(state) if m.status == "success"}
    assert payments.count() == 1
    assert contents <= {"refunded re_000001"}


def test_unregistered_tools_count_as_writes(ledger: Ledger) -> None:
    @tool
    def note(text: str) -> str:
        """Write a note."""
        return f"noted {text}"

    agent = ScriptedAgent([[("note", {"text": "x"}), ("missing", {})]])
    state = agent.graph(node(ledger, [note], None)).invoke({"messages": [("user", "go")]}, CONFIG)
    assert [row.effect for row in ledger.find_intents(tool="note")] == ["write"]
    assert tool_messages(state)[1].status == "error"  # a tool that does not exist never runs
    assert ledger.find_intents(tool="missing") == []


def test_state_updates_are_returned_once(ledger: Ledger) -> None:
    @tool
    def remember(fact: str, tool_call_id: Annotated[str, InjectedToolCallId]) -> Command[Any]:
        """Remember a fact."""
        message = ToolMessage(f"remembered {fact}", tool_call_id=tool_call_id)
        return Command(update={"messages": [message]})

    agent = ScriptedAgent([[("remember", {"fact": "x"})], [("remember", {"fact": "x"})]])
    specs = {"remember": ToolSpec(name="memory.add", effect="write")}
    state = agent.graph(node(ledger, [remember], specs)).invoke(
        {"messages": [("user", "go")]}, CONFIG
    )

    texts = [str(m.content) for m in tool_messages(state)]
    assert texts[0] == "remembered x"
    assert "already ran" in texts[1]


def test_tools_that_cannot_take_injected_values_are_refused(ledger: Ledger) -> None:
    @tool
    def no_key(order_id: str) -> str:
        """Refund an order."""
        return order_id

    @tool
    def visible_key(order_id: str, idempotency_key: str | None = None) -> str:
        """Refund an order."""
        return order_id

    with pytest.raises(TypeError, match="idempotency_key parameter"):
        node(ledger, [no_key], {"no_key": SPECS["refund"]})
    with pytest.raises(TypeError, match="InjectedToolArg"):
        node(ledger, [visible_key], {"visible_key": SPECS["refund"]})
