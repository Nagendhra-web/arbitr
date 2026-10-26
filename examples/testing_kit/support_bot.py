"""A small support agent: Claude with two tools, refunds and SQL, behind Arbitr.

The tests next to it (``test_support_bot.py``) prove what it can never do,
using only the Arbitr pytest plugin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from anthropic import beta_tool

from arbitr import Ledger, ToolSpec
from arbitr.integrations.anthropic import guard_tools

if TYPE_CHECKING:
    import anthropic

    from arbitr.testing import FakePayments

MODEL = "claude-opus-5-5"
SPECS = {
    "refund": ToolSpec(name="payments.refund", effect="financial", idempotency="native"),
    "run_sql": ToolSpec(name="db.execute", effect="write"),
}


class SupportBot:
    """Answers one customer message, calling tools as Claude decides."""

    def __init__(self, client: anthropic.Anthropic, ledger: Ledger, payments: FakePayments) -> None:
        """A bot that refunds through ``payments`` and runs SQL on a (pretend) database."""
        self.client = client
        self.ledger = ledger
        self.payments = payments
        self.sql_run: list[str] = []

    def tools(self) -> list[Any]:
        """The bot's tools, every one guarded by the ledger."""

        @beta_tool
        def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
            """Refund an order."""
            made = self.payments.refund(order_id, amount, idempotency_key=idempotency_key)
            return f"refunded {made['refund_id']}"

        @beta_tool
        def run_sql(sql: str) -> str:
            """Run a SQL statement on the orders database."""
            self.sql_run.append(sql)
            return "ok"

        return list(guard_tools(self.ledger, [refund, run_sql], SPECS))

    def handle(self, message: str) -> str:
        """Answer ``message``. Call inside ``ledger.run(...)``."""
        runner = self.client.beta.messages.tool_runner(
            model=MODEL,
            max_tokens=16000,
            tools=self.tools(),
            messages=[{"role": "user", "content": message}],
        )
        final = ""
        for reply in runner:
            final = "".join(block.text for block in reply.content if block.type == "text")
        return final
