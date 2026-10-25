"""A scheduler process for the fault tests. Kills itself at one step of a due action.

Usage: python scheduled_worker.py LEDGER PAYMENTS MODE CRASH_AT
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench.fakes.payments import FakePayments  # noqa: E402
from fault_worker import KEY, LEASE_TTL, kill_self, spec_for  # noqa: E402

from arbitr.executor import Ledger  # noqa: E402
from arbitr.policy.schema import load_policy  # noqa: E402

POLICY = load_policy("""
version: 1
default: { financial: allow }
rules:
  - id: hold-refunds
    when: { tool: payments.refund }
    then: delay 1s
    reason: Refunds wait a moment so someone can cancel them.
""")
ARGS = {"order_id": "o1", "amount": 25}


def tools_for(mode: str, service: FakePayments) -> dict[str, tuple[object, object]]:
    """The scheduler's tool table: the refund tool in the given mode."""

    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
        return service.refund(order_id, amount, idempotency_key=idempotency_key)

    return {"payments.refund": (spec_for(mode), refund)}


def main() -> None:
    """Run the due actions, crashing at the requested step."""
    ledger_path, payments_path, mode, crash_at = sys.argv[1:5]
    service = FakePayments(payments_path, native=mode == "native")

    def on_step(step: str) -> None:
        if step == crash_at:
            kill_self()

    with Ledger.open(
        ledger_path, POLICY, key=KEY, worker_id="scheduler-1", lease_ttl=LEASE_TTL, on_step=on_step
    ) as ledger:
        ledger.probe_context["payments"] = service
        report = ledger.run_due(tools_for(mode, service))  # type: ignore[arg-type]
    sys.stdout.write(f"{report}\n")


if __name__ == "__main__":
    main()
