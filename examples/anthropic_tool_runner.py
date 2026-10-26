"""Claude with the Anthropic SDK's tool runner, every tool call through the ledger.

Run it: ``python examples/anthropic_tool_runner.py``. It uses a scripted
Claude (``arbitr.testing.anthropic``), so it needs no API key and makes no
network calls. With a real client, pass ``anthropic.Anthropic()`` to
``main`` instead; nothing else changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from _shared import SCRIPT, SPECS, fresh_ledger, report
from anthropic import beta_tool

from arbitr.integrations.anthropic import guard_tools
from arbitr.testing import FakePayments
from arbitr.testing.anthropic import ScriptedClaude

if TYPE_CHECKING:
    import anthropic

MODEL = "claude-opus-5-5"


def main(client: anthropic.Anthropic | None = None) -> int:
    payments = FakePayments()

    @beta_tool
    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        """Refund an order.

        Args:
            order_id: The order to refund.
            amount: How much to refund.
            idempotency_key: Filled in by Arbitr; the model never sees it.
        """
        made = payments.refund(order_id, amount, idempotency_key=idempotency_key)
        return f"refunded {made['refund_id']}"

    @beta_tool
    def run_sql(sql: str) -> str:
        """Run a SQL statement on the orders database."""
        raise AssertionError("never reached in this example")

    scripted = ScriptedClaude(SCRIPT) if client is None else None  # type: ignore[arg-type]
    claude = client or scripted.client()  # type: ignore[union-attr]
    with fresh_ledger() as ledger:
        tools: list[Any] = guard_tools(ledger, [refund, run_sql], SPECS)
        with ledger.run(principal="alice", agent_id="support-bot"):
            runner = claude.beta.messages.tool_runner(
                model=MODEL,
                max_tokens=16000,
                tools=tools,
                messages=[{"role": "user", "content": "Please refund my orders o-1 and o-2."}],
            )
            for message in runner:
                for block in message.content:
                    if block.type == "text":
                        print(f"claude: {block.text}")
        if scripted is not None:
            outputs = [str(result.get("content")) for result in scripted.tool_results()]
            report(outputs, payments.count(), ledger)
    payments.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
