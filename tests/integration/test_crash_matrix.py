"""Exactly-once through a worker crash, through every integration.

Each case makes one tool call through an integration, kills the worker right
after the tool acted (before the ledger recorded it), restarts, and has the
model make the same call again:

- a native tool runs again with the same key and the service deduplicates;
- a probe tool is found by its probe and does not run again;
- a tool with no idempotency ends UNKNOWN and does not run again.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any

import pytest
from agents import Agent, Runner
from anthropic import beta_async_tool, beta_tool
from langchain_core.tools import InjectedToolArg, tool

from arbitr import ActionError, ToolSpec, guard
from arbitr.integrations.anthropic import atool_results, guard_tool, tool_results
from arbitr.integrations.langgraph import guarded_tool_node
from arbitr.integrations.openai_agents import guarded_function_tool
from arbitr.testing import FakePayments, SimulatedCrash, crash_at, restart
from arbitr.testing.anthropic import ScriptedClaude
from arbitr.testing.langgraph import ScriptedAgent, tool_messages
from arbitr.testing.openai_agents import ScriptedModel

if TYPE_CHECKING:
    from arbitr.executor import Ledger

SPECS = {
    "native": ToolSpec(name="payments.refund", effect="financial", idempotency="native"),
    "probe": ToolSpec(
        name="payments.refund", effect="financial", idempotency="probe",
        probe="arbitr.testing.fakes:find_refund",
    ),
    "none": ToolSpec(name="email.send", effect="external_comm"),
}  # fmt: skip
ARGS = {"refund": {"order_id": "o-1", "amount": 25}, "send_email": {"to": "a@example.com"}}


class World:
    """The services the tools act on, and how many times they acted."""

    def __init__(self) -> None:
        self.payments = FakePayments(native=True)
        self.mail: list[str] = []

    def refund(self, order_id: str, amount: float, idempotency_key: str | None) -> str:
        made = self.payments.refund(order_id, amount, idempotency_key=idempotency_key)
        return f"refunded {made['refund_id']}"

    def send(self, to: str) -> str:
        self.mail.append(to)
        return "sent"


Call = Callable[[], str]


def tool_name(kind: str) -> str:
    return "send_email" if kind == "none" else "refund"


# ------------------------------------------------------------------ one call per integration


def via_guard(ledger: Ledger, kind: str, world: World) -> Call:
    if kind == "none":

        def send_email(to: str) -> str:
            return world.send(to)

        fn: Callable[..., Any] = guard(ledger, SPECS[kind])(send_email)
    else:

        def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
            return world.refund(order_id, amount, idempotency_key)

        fn = guard(ledger, SPECS[kind])(refund)

    def call() -> str:
        try:
            return str(fn(**ARGS[tool_name(kind)]))
        except ActionError as stop:
            return stop.to_tool_message()

    return call


def via_guard_async(ledger: Ledger, kind: str, world: World) -> Call:
    if kind == "none":

        async def send_email(to: str) -> str:
            return world.send(to)

        fn: Callable[..., Any] = guard(ledger, SPECS[kind])(send_email)
    else:

        async def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
            return world.refund(order_id, amount, idempotency_key)

        fn = guard(ledger, SPECS[kind])(refund)

    def call() -> str:
        async def main() -> str:
            try:
                return str(await fn(**ARGS[tool_name(kind)]))
            except ActionError as stop:
                return stop.to_tool_message()

        return asyncio.run(main())

    return call


def anthropic_tool(kind: str, world: World, *, asynchronous: bool) -> Any:
    if kind == "none":

        def send_email(to: str) -> str:
            """Send an email."""
            return world.send(to)

        async def send_email_async(to: str) -> str:
            """Send an email."""
            return world.send(to)

        return (
            beta_async_tool(send_email_async, name="send_email")
            if asynchronous
            else beta_tool(send_email)
        )

    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        """Refund an order."""
        return world.refund(order_id, amount, idempotency_key)

    async def refund_async(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        """Refund an order."""
        return world.refund(order_id, amount, idempotency_key)

    return beta_async_tool(refund_async, name="refund") if asynchronous else beta_tool(refund)


def via_anthropic_runner(ledger: Ledger, kind: str, world: World) -> Call:
    guarded = guard_tool(ledger, SPECS[kind], anthropic_tool(kind, world, asynchronous=False))

    def call() -> str:
        name = tool_name(kind)
        claude = ScriptedClaude([[(name, ARGS[name])], "done"])
        runner = claude.client().beta.messages.tool_runner(
            model="claude-opus-5-5", max_tokens=1024, tools=[guarded],
            messages=[{"role": "user", "content": "go"}],
        )  # fmt: skip
        list(runner)
        return str(claude.tool_results()[0].get("content"))

    return call


def via_anthropic_loop(ledger: Ledger, kind: str, world: World) -> Call:
    guarded = guard_tool(ledger, SPECS[kind], anthropic_tool(kind, world, asynchronous=False))

    def call() -> str:
        name = tool_name(kind)
        use = [{"type": "tool_use", "id": "t1", "name": name, "input": ARGS[name]}]
        return str(tool_results(use, [guarded])[0].get("content"))  # type: ignore[list-item]

    return call


def via_anthropic_async_loop(ledger: Ledger, kind: str, world: World) -> Call:
    guarded = guard_tool(ledger, SPECS[kind], anthropic_tool(kind, world, asynchronous=True))

    def call() -> str:
        name = tool_name(kind)
        use = [{"type": "tool_use", "id": "t1", "name": name, "input": ARGS[name]}]
        return str(asyncio.run(atool_results(use, [guarded]))[0].get("content"))

    return call


def via_openai(ledger: Ledger, kind: str, world: World) -> Call:
    if kind == "none":

        def send_email(to: str) -> str:
            """Send an email."""
            return world.send(to)

        fn: Callable[..., Any] = send_email
    else:

        def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
            """Refund an order."""
            return world.refund(order_id, amount, idempotency_key)

        fn = refund
    guarded = guarded_function_tool(ledger, SPECS[kind], fn)

    def call() -> str:
        name = tool_name(kind)
        model = ScriptedModel([[(name, ARGS[name])], "done"])
        agent = Agent(name="bot", tools=[guarded])
        asyncio.run(Runner.run(agent, "go", run_config=model.run_config()))
        return model.tool_outputs()[0]

    return call


def langgraph_tool(kind: str, world: World) -> Any:
    if kind == "none":

        @tool
        def send_email(to: str) -> str:
            """Send an email."""
            return world.send(to)

        return send_email

    @tool
    def refund(
        order_id: str,
        amount: float,
        idempotency_key: Annotated[str | None, InjectedToolArg] = None,
    ) -> str:
        """Refund an order."""
        return world.refund(order_id, amount, idempotency_key)

    return refund


def via_langgraph(ledger: Ledger, kind: str, world: World, *, asynchronous: bool = False) -> Call:
    the_tool = langgraph_tool(kind, world)
    node = guarded_tool_node(ledger, [the_tool], {the_tool.name: SPECS[kind]})

    def call() -> str:
        name = tool_name(kind)
        graph = ScriptedAgent([[(name, ARGS[name])], "done"]).graph(node)
        state_in = {"messages": [("user", "go")]}
        state = asyncio.run(graph.ainvoke(state_in)) if asynchronous else graph.invoke(state_in)
        return str(tool_messages(state)[0].content)

    return call


def via_langgraph_async(ledger: Ledger, kind: str, world: World) -> Call:
    return via_langgraph(ledger, kind, world, asynchronous=True)


INTEGRATIONS = {
    "guard": via_guard,
    "guard-async": via_guard_async,
    "anthropic-runner": via_anthropic_runner,
    "anthropic-loop": via_anthropic_loop,
    "anthropic-async-loop": via_anthropic_async_loop,
    "openai-agents": via_openai,
    "langgraph": via_langgraph,
    "langgraph-async": via_langgraph_async,
}


def crashed(exc: BaseException) -> bool:
    """Whether the worker's death is ``exc`` or what it wraps."""
    seen: list[BaseException] = [exc]
    while seen:
        current = seen.pop()
        if isinstance(current, SimulatedCrash):
            return True
        seen += [e for e in (current.__cause__, current.__context__) if e is not None]
        seen += list(getattr(current, "exceptions", ()))
    return False


@pytest.mark.parametrize("kind", sorted(SPECS))
@pytest.mark.parametrize("integration", sorted(INTEGRATIONS))
def test_a_crash_after_the_tool_acted_never_doubles_the_effect(
    integration: str, kind: str, ledger: Ledger
) -> None:
    world = World()
    ledger.probe_context["payments"] = world.payments
    call = INTEGRATIONS[integration](ledger, kind, world)

    with ledger.run(principal="alice", agent_id="bot", run_id="r-1"):
        with crash_at(ledger, "after_tool"), pytest.raises(BaseException) as died:  # noqa: PT011 - checked below
            call()
        assert crashed(died.value), repr(died.value)
        restart(ledger)
        answer = call()

    (row,) = ledger.find_intents(tool=SPECS[kind].name)
    if kind == "none":
        assert world.mail == ["a@example.com"]
        assert row.state.value == "UNKNOWN"
        assert "may or may not have happened" in answer
    else:
        assert world.payments.count() == 1
        assert (
            world.payments.find_refund("o-1", row.idempotency_key) is not None
        )  # the ledger's key
        assert row.state.value == "SUCCEEDED"
        assert "re_000001" in answer  # a probe recovery answers with what the probe found
    world.payments.close()
