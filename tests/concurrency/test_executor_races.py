"""Many threads and processes call one tool with one idempotency key at once.

The tool has no idempotency of its own (every call to the fake service makes a
refund), so only the ledger stands between the racers and a double refund.
Exactly one racer runs the tool; the others get its receipt or InFlight.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from bench.fakes.payments import FakePayments

from arbitr.core.errors import InFlight
from arbitr.core.spec import ToolSpec
from arbitr.executor import Ledger
from arbitr.policy.schema import load_policy

pytestmark = pytest.mark.sqlite_only  # the Postgres pass deselects these for now

KEY = b"executor-races!!" * 2
POLICY_TEXT = "version: 1\ndefault: { financial: allow }\n"
POLICY = load_policy(POLICY_TEXT)
SPEC = ToolSpec(name="payments.refund", effect="financial")
ARGS = {"order_id": "o1", "amount": 25}
THREADS = 50
PROCESSES = 8

WORKER = """
import sys, time
sys.path.insert(0, sys.argv[4])
from bench.fakes.payments import FakePayments
from arbitr.core.errors import InFlight
from arbitr.core.spec import ToolSpec
from arbitr.executor import Ledger
from arbitr.policy.schema import load_policy

ledger_path, payments_path, start_at = sys.argv[1], sys.argv[2], float(sys.argv[3])
service = FakePayments(payments_path, native=False)

def refund(order_id, amount):
    time.sleep(0.05)
    return service.refund(order_id, amount)

spec = ToolSpec(name="payments.refund", effect="financial")
policy = load_policy({policy!r})
with Ledger.open(ledger_path, policy, key={key!r}, worker_id=f"p{{start_at}}") as ledger:
    with ledger.run("alice", "bot", run_id="r1", resume=True):
        time.sleep(max(0.0, start_at - time.time()))
        try:
            out = ledger.execute(spec, {args!r}, refund, idempotency_key="refund-o1")
            print("result", out["refund_id"])
        except InFlight:
            print("inflight")
service.close()
"""


def _slow_refund(service: FakePayments) -> object:
    def call(order_id: str, amount: float) -> object:
        time.sleep(0.05)  # widen the window in which racers overlap
        return service.refund(order_id, amount)

    return call


def test_fifty_threads_on_one_key_refund_once(tmp_path: Path) -> None:
    service = FakePayments(tmp_path / "payments.db", native=False)
    barrier = threading.Barrier(THREADS)
    outcomes: list[object] = []
    lock = threading.Lock()
    with Ledger.open(tmp_path / "ledger.db", POLICY, key=KEY, worker_id="w") as ledger:
        with ledger.run("alice", "bot", run_id="r1"):
            pass

        def racer() -> None:
            with ledger.run("alice", "bot", run_id="r1", resume=True):
                barrier.wait()
                try:
                    out: object = ledger.execute(
                        SPEC, ARGS, _slow_refund(service), idempotency_key="refund-o1"
                    )
                except InFlight as exc:
                    out = exc
            with lock:
                outcomes.append(out)

        threads = [threading.Thread(target=racer) for _ in range(THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert ledger.verify().ok
    try:
        assert service.count() == 1
    finally:
        service.close()
    results = [o for o in outcomes if isinstance(o, dict)]
    assert len(outcomes) == THREADS
    assert results, "at least the winner returns the result"
    assert all(r == results[0] for r in results)
    assert all(isinstance(o, dict | InFlight) for o in outcomes)


def test_eight_processes_on_one_key_refund_once(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.db"
    payments_path = tmp_path / "payments.db"
    with (
        Ledger.open(ledger_path, POLICY, key=KEY, worker_id="setup") as ledger,
        ledger.run("alice", "bot", run_id="r1"),
    ):
        pass
    FakePayments(payments_path).close()  # create the store before the race
    root = str(Path(__file__).resolve().parents[2])
    script = WORKER.format(policy=POLICY_TEXT, key=KEY, args=ARGS)
    start_at = time.time() + 3.0  # every process starts the call at the same moment
    procs = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(ledger_path),
                str(payments_path),
                str(start_at + i * 1e-6),
                root,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for i in range(PROCESSES)
    ]
    outputs = [p.communicate(timeout=120) for p in procs]
    assert all(p.returncode == 0 for p in procs), [err for _, err in outputs]
    lines = [out.strip() for out, _ in outputs]
    assert all(line in ("result re_000001", "inflight") for line in lines), lines
    assert "result re_000001" in lines
    service = FakePayments(payments_path)
    try:
        assert service.count() == 1
    finally:
        service.close()
    with Ledger.open(ledger_path, POLICY, key=KEY, worker_id="check") as ledger:
        assert ledger.verify().ok
