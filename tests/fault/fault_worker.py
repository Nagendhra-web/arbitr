"""A worker process for the fault-injection tests. Kills itself at one step boundary.

Usage: python fault_worker.py LEDGER PAYMENTS MODE CRASH_AT

MODE is the tool's idempotency (native, probe or none). CRASH_AT is a step
name from the executor (after_decision_commit, ..., after_side_effect), or
"never" to run to the end. The process is killed with a real signal, so no
cleanup code runs: exactly what a power cut or OOM kill looks like.
"""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from bench.fakes.payments import FakePayments  # noqa: E402

from arbitr.core.spec import ToolSpec  # noqa: E402
from arbitr.core.states import IntentState  # noqa: E402
from arbitr.executor import Ledger  # noqa: E402
from arbitr.policy.schema import load_policy  # noqa: E402

KEY = b"fault-injection!" * 2
POLICY = load_policy("version: 1\ndefault: { financial: allow }\n")
LEASE_TTL = 0.5


def spec_for(mode: str) -> ToolSpec:
    """The refund tool with the given idempotency mode."""
    if mode == "probe":
        return ToolSpec(
            name="payments.refund",
            effect="financial",
            idempotency="probe",
            probe="bench.fakes.probes:find_refund",
        )
    return ToolSpec(name="payments.refund", effect="financial", idempotency=mode)  # type: ignore[arg-type]


# Before the EXECUTING commit nothing can have run, so every mode just runs. After
# it, a none tool must stay UNKNOWN (no silent re-run), with the refund made or not.
_NONE_AFTER_COMMIT = {
    "after_executing_commit": (IntentState.UNKNOWN, 0),
    "before_call": (IntentState.UNKNOWN, 0),
    "after_side_effect": (IntentState.UNKNOWN, 1),
}


def expected(mode: str, step: str) -> tuple[IntentState, int]:
    """The exact final state and refund count after a crash at ``step``."""
    if mode == "none" and step in _NONE_AFTER_COMMIT:
        return _NONE_AFTER_COMMIT[step]
    return (IntentState.SUCCEEDED, 1)


def kill_self() -> None:
    """Die at once, with no cleanup (TerminateProcess on Windows, SIGKILL elsewhere)."""
    sig = getattr(signal, "SIGKILL", signal.SIGTERM)
    os.kill(os.getpid(), sig)


def main() -> None:
    """Run one refund, crashing at the requested step."""
    ledger_path, payments_path, mode, crash_at = sys.argv[1:5]
    service = FakePayments(payments_path, native=mode == "native")

    def on_step(step: str) -> None:
        if step == crash_at:
            kill_self()

    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
        return service.refund(order_id, amount, idempotency_key=idempotency_key)

    with Ledger.open(
        ledger_path, POLICY, key=KEY, worker_id="worker-1", lease_ttl=LEASE_TTL, on_step=on_step
    ) as ledger:
        ledger.probe_context["payments"] = service
        with ledger.run("alice", "bot", run_id="run-1"):
            result = ledger.execute(spec_for(mode), {"order_id": "o1", "amount": 25}, refund)
    sys.stdout.write(f"{result}\n")


if __name__ == "__main__":
    main()
