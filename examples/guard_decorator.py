"""The guard decorator: plain functions that always go through the ledger.

Run it: ``python examples/guard_decorator.py``. No model, no network.
"""

from __future__ import annotations

from _shared import REFUND, RUN_SQL, fresh_ledger, report

from arbitr import ActionError, guard
from arbitr.testing import FakePayments


def main() -> int:
    payments = FakePayments()
    with fresh_ledger() as ledger:

        @guard(ledger, REFUND)
        def refund(order_id: str, amount: float, *, idempotency_key: str | None = None) -> object:
            return payments.refund(order_id, amount, idempotency_key=idempotency_key)

        @guard(ledger, RUN_SQL)
        def run_sql(sql: str) -> str:
            raise AssertionError("never reached in this example")

        calls = [
            lambda: refund("o-1", 25),
            lambda: refund("o-1", 25),  # a retry gets the first refund's receipt
            lambda: run_sql("DROP TABLE orders"),
            lambda: refund("o-2", 500),
        ]
        outputs: list[str] = []
        with ledger.run(principal="alice", agent_id="support-bot"):
            for call in calls:
                try:
                    outputs.append(str(call()))
                except ActionError as stop:
                    outputs.append(stop.to_tool_message())
        report(outputs, payments.count(), ledger)
    payments.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
