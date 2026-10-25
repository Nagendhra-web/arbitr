"""Races the protocol model found: stale probes, failed unknowns, lost leases, stuck approvals."""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import InFlight, StorageError, UnknownOutcome
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.credentials import EnvCredentials
from arbitr.executor import Ledger, current_run
from arbitr.policy.schema import load_policy
from arbitr.storage.sqlite import Transaction

if TYPE_CHECKING:
    from pathlib import Path

KEY = b"protocol-races!!" * 2
POLICY = load_policy("version: 1\ndefault: { financial: allow }\n")
ARGS = {"order_id": "o1", "amount": 5}


class _Crash(BaseException):
    """Stands in for the worker process dying."""


def crash_before_call(ledger: Ledger, spec: ToolSpec) -> str:
    def stop(step: str) -> None:
        if step == "after_executing_commit":
            raise _Crash

    ledger.on_step = stop
    try:
        ledger.execute(spec, ARGS, lambda **kwargs: None)
    except _Crash:
        pass
    finally:
        ledger.on_step = None
    run = current_run()
    assert run is not None
    return run.last_idempotency_key


class RacingFinder:
    """A probe target. On the first probe, a second worker recovers the same intent."""

    def __init__(self, path: Path, spec: ToolSpec, calls: list[str]) -> None:
        self.path, self.spec, self.calls = path, spec, calls
        self.raced = False

    def find_refund(self, order_id: str, key: str) -> object:
        if not self.raced:
            self.raced = True
            with (
                Ledger.open(self.path, POLICY, key=KEY, worker_id="w2", lease_ttl=0) as two,
                two.run("alice", "bot", run_id="r1", resume=True),
            ):
                two.probe_context["payments"] = self
                with contextlib.suppress(UnknownOutcome):  # attempt 2 timed out: UNKNOWN again
                    two.execute(self.spec, ARGS, self.times_out)
        return None  # the side effect is not visible (yet)

    def times_out(self, order_id: str, amount: float, idempotency_key: str) -> object:
        self.calls.append("w2")
        raise TimeoutError("no response")


def test_a_stale_probe_answer_never_starts_another_attempt(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    spec = ToolSpec(name="payments.refund", effect="financial", idempotency="probe",
                    probe="bench.fakes.probes:find_refund")  # fmt: skip
    calls: list[str] = []
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=0) as one:
        one.probe_context["payments"] = RacingFinder(path, spec, calls)
        with one.run("alice", "bot", run_id="r1"):
            crash_before_call(one, spec)
        with one.run("alice", "bot", run_id="r1", resume=True), pytest.raises(InFlight):
            # w1 probes, finds nothing, but w2 ran attempt 2 meanwhile: w1 must not run.
            one.execute(spec, ARGS, lambda **kw: calls.append("w1"))
    assert calls == ["w2"]


def test_an_unknown_recorded_as_failed_never_runs_again_by_itself(tmp_path: Path) -> None:
    policy = load_policy("version: 1\non_unknown: fail\ndefault: { financial: allow }\n")
    spec = ToolSpec(name="payments.refund", effect="financial")
    calls: list[int] = []
    with Ledger.open(tmp_path / "l.db", policy, key=KEY, worker_id="w1", lease_ttl=0) as led:
        with led.run("alice", "bot", run_id="r1"):
            crash_before_call(led, spec)
        with led.run("alice", "bot", run_id="r1", resume=True) as run:
            with pytest.raises(UnknownOutcome, match="recorded as failed"):
                led.execute(spec, ARGS, lambda **kw: calls.append(1))
            with pytest.raises(UnknownOutcome, match="will not run again"):
                led.execute(spec, ARGS, lambda **kw: calls.append(1))
            row = led.intent_by_key(run.last_idempotency_key)
    assert calls == []
    assert row is not None
    assert row.state == IntentState.FAILED


def test_a_plain_failure_can_still_be_retried(tmp_path: Path) -> None:
    policy = load_policy("version: 1\non_unknown: fail\ndefault: { financial: allow }\n")
    spec = ToolSpec(name="payments.refund", effect="financial")
    calls: list[int] = []

    def flaky(order_id: str, amount: float) -> str:
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("card declined")  # a clear failure: the tool did not act
        return "ok"

    with Ledger.open(tmp_path / "l.db", policy, key=KEY) as led, led.run("alice", "bot"):
        with pytest.raises(ValueError, match="declined"):
            led.execute(spec, ARGS, flaky)
        assert led.execute(spec, ARGS, flaky) == "ok"


def test_the_lease_is_confirmed_before_a_late_call(tmp_path: Path) -> None:
    """A slow credential fetch outlives the lease; another worker takes over meanwhile."""
    path = tmp_path / "ledger.db"
    spec = ToolSpec(name="payments.refund", effect="financial", idempotency="native",
                    credentials=("stripe",))  # fmt: skip
    calls: list[str] = []

    def call(worker: str) -> Callable[..., str]:
        def fn(order_id: str, amount: float, idempotency_key: str, credentials: object) -> str:
            calls.append(worker)
            return "ok"

        return fn

    class SlowCredentials(EnvCredentials):
        stolen = False

        def get(self, name: str) -> str:
            if not self.stolen:
                self.stolen = True
                time.sleep(0.3)  # longer than the lease
                with (
                    Ledger.open(path, POLICY, key=KEY, worker_id="w2", credentials=EnvCredentials(
                        environ={"ARBITR_CRED_STRIPE": "x"})) as two,
                    two.run("alice", "bot", run_id="r1", resume=True),
                ):  # fmt: skip
                    two.execute(spec, ARGS, call("w2"))
            return super().get(name)

    creds = SlowCredentials(environ={"ARBITR_CRED_STRIPE": "x"})
    with (
        Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=0.2, credentials=creds) as one,
        one.run("alice", "bot", run_id="r1"),
        pytest.raises(InFlight),
    ):
        one.execute(spec, ARGS, call("w1"))
    assert calls == ["w2"]


def test_the_heartbeat_survives_a_transient_storage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ledger.db"
    spec = ToolSpec(name="payments.refund", effect="financial", idempotency="native")
    real = Transaction.heartbeat
    failures = [StorageError("database is locked")]

    def flaky_heartbeat(self: Transaction, *args: object, **kwargs: object) -> object:
        if failures:
            raise failures.pop()
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Transaction, "heartbeat", flaky_heartbeat)
    seen: list[str] = []

    def slow(order_id: str, amount: float, idempotency_key: str) -> str:
        time.sleep(0.9)  # several lease lifetimes
        with (
            Ledger.open(path, POLICY, key=KEY, worker_id="w2") as two,
            two.run("alice", "bot", run_id="r1", resume=True),
        ):
            try:
                two.execute(spec, ARGS, lambda **kw: seen.append("w2 ran"))
            except InFlight:
                seen.append("in flight")
        return "ok"

    with (
        Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=0.3) as one,
        one.run("alice", "bot", run_id="r1"),
    ):
        assert one.execute(spec, ARGS, slow) == "ok"
    assert seen == ["in flight"]
    assert not failures


def test_recovery_reports_approved_actions_that_never_started(tmp_path: Path) -> None:
    spec = ToolSpec(name="payments.refund", effect="financial")

    def stop(step: str) -> None:
        if step == "after_decision_commit":
            raise _Crash

    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY, lease_ttl=0, on_step=stop) as led:
        with led.run("alice", "bot", run_id="r1"):
            with pytest.raises(_Crash):
                led.execute(spec, ARGS, lambda **kw: None)
            row = led.intent_by_key(current_run().last_idempotency_key)  # type: ignore[union-attr]
        led.on_step = None
        time.sleep(0.01)
        report = led.recover_stale()
    assert row is not None
    assert [(r.intent_id, r.state) for r in report] == [(row.intent_id, IntentState.APPROVED)]
    assert "next call with the same key" in report[0].action
