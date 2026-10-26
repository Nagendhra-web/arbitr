"""An OpenAI Agents SDK agent whose function tools go through the ledger.

Run it: ``python examples/openai_agents_runner.py``. It uses a scripted model
(``arbitr.testing.openai_agents``), so it needs no API key and makes no
network calls. With a real model, drop the ``run_config`` argument.
"""

from __future__ import annotations

import asyncio

from _shared import REFUND, RUN_SQL, SCRIPT, fresh_ledger, report
from agents import Agent, Runner

from arbitr.integrations.openai_agents import guarded_function_tool
from arbitr.testing import FakePayments
from arbitr.testing.openai_agents import ScriptedModel


async def run() -> int:
    payments = FakePayments()
    model = ScriptedModel(SCRIPT)  # type: ignore[arg-type]
    with fresh_ledger() as ledger:

        @guarded_function_tool(ledger, REFUND)
        def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
            """Refund an order.

            Args:
                order_id: The order to refund.
                amount: How much to refund.
                idempotency_key: Filled in by Arbitr; the model never sees it.
            """
            made = payments.refund(order_id, amount, idempotency_key=idempotency_key)
            return f"refunded {made['refund_id']}"

        @guarded_function_tool(ledger, RUN_SQL)
        def run_sql(sql: str) -> str:
            """Run a SQL statement on the orders database."""
            raise AssertionError("never reached in this example")

        agent = Agent(
            name="support-bot", instructions="Help with refunds.", tools=[refund, run_sql]
        )
        with ledger.run(principal="alice", agent_id="support-bot"):
            result = await Runner.run(
                agent, "Please refund my orders o-1 and o-2.", run_config=model.run_config()
            )
        print(f"agent: {result.final_output}")
        report(model.tool_outputs(), payments.count(), ledger)
    payments.close()
    return 0


def main() -> int:
    return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
