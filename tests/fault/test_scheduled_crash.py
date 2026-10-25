"""Kill the scheduler at every step of a due action, then let a new scheduler finish it.

Nobody calls a scheduled action again (the agent was told not to), so the
scheduler itself must recover what a crashed scheduler left behind.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest
from bench.fakes.payments import FakePayments

from arbitr.core.errors import ActionScheduled
from arbitr.executor import Ledger

pytestmark = pytest.mark.sqlite_only  # the Postgres pass deselects these for now

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from fault_worker import KEY, LEASE_TTL, expected, spec_for  # noqa: E402
from scheduled_worker import ARGS, POLICY, tools_for  # noqa: E402

STEPS = ["before_executing_commit", "after_executing_commit", "before_call", "after_side_effect"]
WINDOW = 1.0


def schedule(ledger_path: Path, payments_path: Path, mode: str) -> str:
    service = FakePayments(payments_path, native=mode == "native")
    try:
        with (
            Ledger.open(ledger_path, POLICY, key=KEY, worker_id="agent") as ledger,
            ledger.run("alice", "bot", run_id="run-1"),
            pytest.raises(ActionScheduled) as err,
        ):
            ledger.execute(spec_for(mode), ARGS, tools_for(mode, service)["payments.refund"][1])  # type: ignore[arg-type]
    finally:
        service.close()
    return err.value.intent_id


@pytest.mark.parametrize("step", STEPS)
@pytest.mark.parametrize("mode", ["native", "probe", "none"])
def test_a_scheduler_crash_never_doubles_the_side_effect(
    tmp_path: Path, mode: str, step: str
) -> None:
    ledger_path, payments_path = tmp_path / "ledger.db", tmp_path / "payments.db"
    intent_id = schedule(ledger_path, payments_path, mode)
    time.sleep(WINDOW + 0.1)
    proc = subprocess.run(
        [sys.executable, str(HERE / "scheduled_worker.py"), str(ledger_path),
         str(payments_path), mode, step],
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert proc.returncode != 0, "the scheduler should have been killed"
    time.sleep(LEASE_TTL + 0.3)

    service = FakePayments(payments_path, native=mode == "native")
    try:
        with Ledger.open(ledger_path, POLICY, key=KEY, worker_id="scheduler-2") as ledger:
            ledger.probe_context["payments"] = service
            report = ledger.run_due(tools_for(mode, service))  # type: ignore[arg-type]
            row = ledger.intent(intent_id)
            assert ledger.verify().ok
        refunds = service.count("o1")
    finally:
        service.close()

    assert [r.intent_id for r in report] == [intent_id]
    assert row is not None
    assert (row.state, refunds) == expected(mode, step), f"{mode} crashed at {step}"
