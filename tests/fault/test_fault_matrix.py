"""The fault-injection matrix: kill a real worker at every step, then recover.

For every idempotency mode and every step boundary of the execution protocol,
a worker process is killed with a real signal at that step. A second worker
then retries the same call after the lease has run out. The side effect must
happen at most once for ``native`` and ``probe`` tools, and a ``none`` tool
must end in SUCCEEDED or UNKNOWN, never in a silent second execution.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest
from bench.fakes.payments import FakePayments

from arbitr.core.errors import UnknownOutcome
from arbitr.core.states import IntentState
from arbitr.executor import Ledger, current_run

pytestmark = pytest.mark.sqlite_only  # the Postgres pass deselects these for now

WORKER = Path(__file__).with_name("fault_worker.py")
sys.path.insert(0, str(WORKER.parent))

from fault_worker import KEY, LEASE_TTL, POLICY, expected, spec_for  # noqa: E402

STEPS = [
    "after_decision_commit",
    "before_executing_commit",
    "after_executing_commit",
    "before_call",
    "after_side_effect",
]
MODES = ["native", "probe", "none"]


def crash_worker(ledger: Path, payments: Path, mode: str, step: str) -> int:
    proc = subprocess.run(
        [sys.executable, str(WORKER), str(ledger), str(payments), mode, step],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return proc.returncode


def retry(ledger_path: Path, payments_path: Path, mode: str) -> tuple[object, IntentState | None]:
    service = FakePayments(payments_path, native=mode == "native")

    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
        return service.refund(order_id, amount, idempotency_key=idempotency_key)

    try:
        with Ledger.open(ledger_path, POLICY, key=KEY, worker_id="worker-2") as ledger:
            ledger.recover_stale()  # what a restarted worker does first
            ledger.probe_context["payments"] = service
            with ledger.run("alice", "bot", run_id="run-1", resume=True):
                try:
                    result: object = ledger.execute(
                        spec_for(mode), {"order_id": "o1", "amount": 25}, refund
                    )
                except UnknownOutcome as exc:
                    result = exc
                run = current_run()
                assert run is not None
                row = ledger.intent_by_key(run.last_idempotency_key)
            assert ledger.verify().ok
        return result, row.state if row else None
    finally:
        service.close()


@pytest.mark.parametrize("step", STEPS)
@pytest.mark.parametrize("mode", MODES)
def test_a_crash_at_any_step_never_doubles_the_side_effect(
    tmp_path: Path, mode: str, step: str
) -> None:
    ledger_path = tmp_path / "ledger.db"
    payments_path = tmp_path / "payments.db"
    code = crash_worker(ledger_path, payments_path, mode, step)
    assert code != 0, "the worker should have been killed"
    time.sleep(LEASE_TTL + 0.3)  # let the dead worker's lease run out

    result, state = retry(ledger_path, payments_path, mode)
    service = FakePayments(payments_path)
    try:
        refunds = service.count("o1")
    finally:
        service.close()

    assert (state, refunds) == expected(mode, step), f"{mode} crashed at {step}"
    if state == IntentState.SUCCEEDED:
        assert isinstance(result, dict)
    else:
        assert isinstance(result, UnknownOutcome)


@pytest.mark.parametrize("mode", MODES)
def test_without_a_crash_every_mode_runs_once(tmp_path: Path, mode: str) -> None:
    ledger_path = tmp_path / "ledger.db"
    payments_path = tmp_path / "payments.db"
    assert crash_worker(ledger_path, payments_path, mode, "never") == 0
    result, state = retry(ledger_path, payments_path, mode)  # the retry deduplicates
    service = FakePayments(payments_path)
    try:
        assert service.count("o1") == 1
    finally:
        service.close()
    assert state == IntentState.SUCCEEDED
    assert isinstance(result, dict)
