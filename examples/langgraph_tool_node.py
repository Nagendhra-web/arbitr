"""A LangGraph agent whose ToolNode sends every tool call through the ledger.

Run it: ``python examples/langgraph_tool_node.py``. The model's side is a
scripted node (``arbitr.testing.langgraph``), so it needs no API key and makes
no network calls. In a real graph, put your chat model node where the
scripted one is; the tool node stays the same.
"""

from __future__ import annotations

from typing import Annotated

from _shared import SCRIPT, SPECS, fresh_ledger, report
from langchain_core.tools import InjectedToolArg, tool

from arbitr.integrations.langgraph import guarded_tool_node
from arbitr.testing import FakePayments
from arbitr.testing.langgraph import ScriptedAgent, tool_messages


def main() -> int:
    payments = FakePayments()

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
        """Run a SQL statement on the orders database."""
        raise AssertionError("never reached in this example")

    with fresh_ledger() as ledger:
        agent = ScriptedAgent(SCRIPT)  # type: ignore[arg-type]
        # Who the agent acts for comes from your app (here a fixed user), never
        # from config a client could send. One LangGraph thread is one ledger run.
        tools = guarded_tool_node(ledger, [refund, run_sql], SPECS, principal="alice")
        graph = agent.graph(tools)
        config = {"configurable": {"thread_id": "support-1"}}
        state = graph.invoke({"messages": [("user", "Please refund o-1 and o-2.")]}, config)
        print(f"agent: {state['messages'][-1].content}")
        outputs = [str(message.content) for message in tool_messages(state)]
        report(outputs, payments.count(), ledger)
    payments.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
