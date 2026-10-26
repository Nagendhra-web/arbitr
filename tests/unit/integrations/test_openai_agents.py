"""The OpenAI Agents adapter, driven by the SDK's own Runner against a scripted model."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Annotated

import agents
import pytest
from agents import Agent, FunctionTool, RunContextWrapper, Runner, function_tool
from agents.exceptions import UserError

from adapter_support import KEY, POLICY, REFUND, SQL
from arbitr.core.errors import RunContextError
from arbitr.core.spec import ToolSpec
from arbitr.executor import Ledger, current_run
from arbitr.integrations.openai_agents import guard_function_tool, guarded_function_tool
from arbitr.testing.openai_agents import ScriptedModel

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from bench.fakes.payments import FakePayments


def make_tools(ledger: Ledger, payments: FakePayments, ran: list[str]) -> list[FunctionTool]:
    @guarded_function_tool(ledger, REFUND)
    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        """Refund an order.

        Args:
            order_id: The order to refund.
            amount: How much to refund.
        """
        made = payments.refund(order_id, amount, idempotency_key=idempotency_key)
        return f"refunded {made['refund_id']}"

    @guarded_function_tool(ledger, SQL)
    async def run_sql(sql: str) -> str:
        """Run a SQL statement."""
        ran.append(sql)
        return "ok"

    return [refund, run_sql]


def play(agent: Agent, model: ScriptedModel, prompt: str = "go") -> object:
    return asyncio.run(Runner.run(agent, prompt, run_config=model.run_config())).final_output


def test_runner_runs_allowed_calls_once_and_blocks_the_rest(
    ledger: Ledger, payments: FakePayments
) -> None:
    ran: list[str] = []
    model = ScriptedModel([
        [("refund", {"order_id": "o-1", "amount": 25})],
        [("refund", {"order_id": "o-1", "amount": 25})],  # the model retries
        [("run_sql", {"sql": "DROP TABLE customers"})],
        [("refund", {"order_id": "o-2", "amount": 500})],
        "All done.",
    ])  # fmt: skip
    agent = Agent(name="support", tools=make_tools(ledger, payments, ran))

    with ledger.run(principal="alice", agent_id="support"):
        final = play(agent, model)

    outputs = model.tool_outputs()
    assert outputs[0] == outputs[1] == "refunded re_000001"
    assert outputs[2].startswith("Blocked by policy 'no-destructive-sql'")
    assert "needs human approval" in outputs[3]
    assert payments.count() == 1
    assert ran == []
    assert final == "All done."


def test_parallel_calls_in_one_turn(ledger: Ledger, payments: FakePayments) -> None:
    model = ScriptedModel([[
        ("refund", {"order_id": "o-3", "amount": 5}),
        ("refund", {"order_id": "o-4", "amount": 6}),
        ("run_sql", {"sql": "SELECT 1"}),
    ]])  # fmt: skip
    ran: list[str] = []
    agent = Agent(name="support", tools=make_tools(ledger, payments, ran))
    with ledger.run(principal="alice", agent_id="support"):
        play(agent, model)
    assert payments.count() == 2
    assert ran == ["SELECT 1"]


def test_the_model_never_sees_or_sets_injected_parameters(
    ledger: Ledger, payments: FakePayments
) -> None:
    refund = make_tools(ledger, payments, [])[0]
    assert "idempotency_key" not in refund.params_json_schema["properties"]
    assert "idempotency_key" not in refund.params_json_schema["required"]

    model = ScriptedModel([
        [("refund", {"order_id": "o-9", "amount": 5, "idempotency_key": "model-chosen"})],
        [("refund", {"order_id": "o-9", "amount": 5, "idempotency_key": "another"})],
    ])  # fmt: skip
    with ledger.run(principal="alice", agent_id="support"):
        play(Agent(name="support", tools=[refund]), model)
    assert payments.count() == 1


def test_tool_errors_are_recorded_as_failures_and_can_run_again(ledger: Ledger) -> None:
    attempts: list[int] = []

    @guarded_function_tool(ledger, ToolSpec(name="orders.lookup", effect="read"))
    def lookup(order_id: str) -> str:
        """Look up an order."""
        attempts.append(1)
        if len(attempts) == 1:
            raise ValueError("order service said no")
        return f"order {order_id}"

    model = ScriptedModel([
        [("lookup", {"order_id": "o-5"})],
        [("lookup", {"order_id": "o-5"})],
    ])  # fmt: skip
    with ledger.run(principal="alice", agent_id="support"):
        play(Agent(name="support", tools=[lookup]), model)

    outputs = model.tool_outputs()
    assert outputs[0] == "An error occurred while running the tool. Please try again."
    assert outputs[1] == "order o-5"  # not a stored error: the retry ran
    assert len(attempts) == 2


def test_a_custom_failure_function_writes_the_error_text(ledger: Ledger) -> None:
    async def explain(ctx: RunContextWrapper[object], error: Exception) -> str:
        return f"lookup failed: {error}"

    @guarded_function_tool(ledger, ToolSpec(name="orders.lookup", effect="read"),
                           failure_error_function=explain)  # fmt: skip
    def lookup(order_id: str) -> str:
        """Look up an order."""
        raise KeyError(order_id)

    model = ScriptedModel([[("lookup", {"order_id": "o-6"})]])
    with ledger.run(principal="alice", agent_id="support"):
        play(Agent(name="support", tools=[lookup]), model)
    assert model.tool_outputs() == ["lookup failed: 'o-6'"]


def test_without_a_failure_function_errors_end_the_run(ledger: Ledger) -> None:
    @guarded_function_tool(ledger, ToolSpec(name="orders.lookup", effect="read"),
                           failure_error_function=None)  # fmt: skip
    def lookup(order_id: str) -> str:
        """Look up an order."""
        raise KeyError(order_id)

    model = ScriptedModel([[("lookup", {"order_id": "o-7"})]])
    with ledger.run(principal="alice", agent_id="support"), pytest.raises(Exception, match="o-7"):
        play(Agent(name="support", tools=[lookup]), model)


def test_calls_outside_a_ledger_run_fail_closed(ledger: Ledger, payments: FakePayments) -> None:
    model = ScriptedModel([[("run_sql", {"sql": "SELECT 1"})]])
    ran: list[str] = []
    agent = Agent(name="support", tools=make_tools(ledger, payments, ran))
    with pytest.raises(UserError) as caught:  # the SDK wraps what a tool raises
        play(agent, model)
    assert isinstance(caught.value.__cause__, RunContextError)
    assert ran == []


def test_guard_an_existing_tool_and_bad_arguments(ledger: Ledger) -> None:
    @function_tool(failure_error_function=None)
    def echo(text: str) -> str:
        """Echo text."""
        return text

    guarded = guard_function_tool(ledger, ToolSpec(name="echo", effect="read"), echo)
    model = ScriptedModel([[("echo", {"text": "hi"})]])
    with ledger.run(principal="alice", agent_id="support"):
        play(Agent(name="support", tools=[guarded]), model)
    assert model.tool_outputs() == ["hi"]

    async def direct() -> object:
        with ledger.run(principal="alice", agent_id="support"):
            return await guarded.on_invoke_tool(None, "not json")  # type: ignore[arg-type]

    assert "valid JSON" in str(asyncio.run(direct()))


def test_the_ledger_can_be_given_lazily(ledger: Ledger) -> None:
    @guarded_function_tool(lambda: ledger)
    def note(text: str) -> str:
        """Write a note."""
        return f"noted {text}"

    model = ScriptedModel([[("note", {"text": "x"})]])
    with ledger.run(principal="alice", agent_id="support"):
        play(Agent(name="support", tools=[note]), model)
    assert model.tool_outputs() == ["noted x"]
    rows = ledger.find_intents(tool="note")
    assert [row.effect for row in rows] == ["write"]  # no spec: counted as a write


# ------------------------------------------------------------------ review fixes

SECRET = "cred-" + "value-9021"


class Creds:
    def get(self, name: str) -> str:
        return SECRET


@pytest.fixture
def cred_ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "c.db", POLICY, key=KEY, credentials=Creds()) as led:
        yield led


def test_credentials_reach_the_function_and_never_the_sdk(
    cred_ledger: Ledger, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(agents._debug, "DONT_LOG_TOOL_DATA", False)  # the SDK logs tool input
    seen: list[object] = []
    spec = ToolSpec(name="crm.update", effect="write", credentials=("crm",))

    @guarded_function_tool(cred_ledger, spec)  # strict mode, the SDK's default
    def crm_update(contact: str, credentials: dict[str, str] | None = None) -> str:
        """Update a CRM contact."""
        seen.append(credentials)
        return f"updated {contact} with {credentials}"  # a careless tool echoes it

    assert set(crm_update.params_json_schema["properties"]) == {"contact"}
    model = ScriptedModel([[("crm_update", {"contact": "c-1"})]])
    logs = caplog.at_level(logging.DEBUG, logger="openai.agents")
    with logs, cred_ledger.run(principal="alice", agent_id="support"):
        play(Agent(name="support", tools=[crm_update]), model)

    assert seen == [{"crm": SECRET}]
    assert caplog.records  # the SDK did log tool data
    assert all(SECRET not in record.getMessage() for record in caplog.records)
    assert SECRET not in model.tool_outputs()[0]
    assert all(SECRET not in event.payload for event in cred_ledger.events())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_the_function_gets_the_ledgers_key(ledger: Ledger, asynchronous: bool) -> None:
    got: list[tuple[str | None, str]] = []

    def record(key: str | None) -> str:
        handle = current_run()
        got.append((key, handle.last_idempotency_key if handle else ""))
        return "ok"

    if asynchronous:

        async def refund(order_id: str, idempotency_key: str | None = None) -> str:
            """Refund an order."""
            return record(idempotency_key)
    else:

        def refund(order_id: str, idempotency_key: str | None = None) -> str:
            """Refund an order."""
            return record(idempotency_key)

    tool = guarded_function_tool(ledger, REFUND, refund)
    model = ScriptedModel([[("refund", {"order_id": "o-1", "idempotency_key": "forged"})]])
    with ledger.run(principal="alice", agent_id="support"):
        play(Agent(name="support", tools=[tool]), model)
    ((key, expected),) = got
    assert key == expected
    assert key not in (None, "forged")


def test_context_parameters_and_annotations_still_work(ledger: Ledger) -> None:
    @guarded_function_tool(ledger, REFUND)
    def refund(
        ctx: RunContextWrapper[object],
        order_id: Annotated[str, "the order"],
        idempotency_key: str | None = None,
    ) -> str:
        """Refund an order."""
        return f"refunded {order_id} for {type(ctx).__name__}"

    assert set(refund.params_json_schema["properties"]) == {"order_id"}
    model = ScriptedModel([[("refund", {"order_id": "o-2"})]])
    with ledger.run(principal="alice", agent_id="support"):
        play(Agent(name="support", tools=[refund]), model)
    assert model.tool_outputs()[0].startswith("refunded o-2 for ")


def test_tools_that_cannot_take_injected_values_are_refused(ledger: Ledger) -> None:
    def no_key(order_id: str) -> str:
        """Refund an order."""
        return order_id

    with pytest.raises(TypeError, match="idempotency_key parameter"):
        guarded_function_tool(ledger, REFUND, no_key)

    @function_tool(failure_error_function=None)
    def plain_refund(order_id: str) -> str:
        """Refund an order."""
        return order_id

    with pytest.raises(TypeError, match="idempotency_key parameter"):
        guard_function_tool(ledger, REFUND, plain_refund)
    creds = ToolSpec(name="crm.update", effect="write", credentials=("crm",))
    with pytest.raises(TypeError, match="guarded_function_tool"):
        guard_function_tool(ledger, creds, plain_refund)


def test_needs_approval_is_the_sdks_own_and_still_works(ledger: Ledger) -> None:
    ran: list[str] = []

    @guarded_function_tool(ledger, SQL, needs_approval=True)
    def run_sql(sql: str) -> str:
        """Run SQL."""
        ran.append(sql)
        return "ok"

    model = ScriptedModel([[("run_sql", {"sql": "SELECT 1"})]])
    with ledger.run(principal="alice", agent_id="support"):
        result = asyncio.run(
            Runner.run(Agent(name="support", tools=[run_sql]), "go", run_config=model.run_config())
        )
    assert result.interruptions  # the SDK paused for its own approval
    assert ran == []
    assert ledger.find_intents(tool="db.execute") == []  # nothing reached the ledger yet


def test_a_timeout_mid_call_is_unknown_and_not_run_again(ledger: Ledger) -> None:
    sent: list[str] = []

    @guarded_function_tool(ledger, ToolSpec(name="email.send", effect="external_comm"), timeout=0.2)
    async def send_email(to: str) -> str:
        """Send an email."""
        sent.append(to)
        await asyncio.sleep(5)  # the mail went out; the reply never comes in time
        return "sent"

    model = ScriptedModel([[("send_email", {"to": "a@example.com"})]] * 2)
    with ledger.run(principal="alice", agent_id="support"):
        play(Agent(name="support", tools=[send_email]), model)

    assert sent == ["a@example.com"]
    (row,) = ledger.find_intents(tool="email.send")
    assert row.state.value == "UNKNOWN"
    assert "may or may not have happened" in model.tool_outputs()[1]
