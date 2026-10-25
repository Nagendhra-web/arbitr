"""Executor edge paths: resumed terminal states, missing records and odd results."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import (
    ActionDenied,
    ActionScheduled,
    ApprovalRejected,
    IntentError,
    LedgerUnavailable,
    StorageError,
    UnknownOutcome,
)
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.credentials import EnvCredentials
from arbitr.executor import Ledger, _Counters, _scrub, current_run
from arbitr.policy.schema import load_policy
from arbitr.storage.sqlite import Transaction

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"executor-edges!!" * 2
POLICY = load_policy("""
version: 1
default: { financial: allow }
rules:
  - id: no-drops
    when: { tool: db.exec }
    then: deny
    reason: No SQL here.
  - id: hold
    when: { tool: payments.payout }
    then: delay 1s
    reason: Wait.
""")
REFUND = ToolSpec(name="payments.refund", effect="financial")
ARGS = {"order_id": "o1", "amount": 5}


class _Crash(BaseException):
    """Stands in for the worker process dying."""


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY, worker_id="w1", lease_ttl=0) as led:
        yield led


def crash_at(ledger: Ledger, step: str, spec: ToolSpec, args: dict[str, object]) -> None:
    def stop(name: str) -> None:
        if name == step:
            raise _Crash

    ledger.on_step = stop
    try:
        with pytest.raises(_Crash):
            ledger.execute(spec, args, lambda **kw: None)
    finally:
        ledger.on_step = None


def test_a_denied_action_stays_denied_when_called_again(ledger: Ledger) -> None:
    drop = ToolSpec(name="db.exec", effect="write")
    with ledger.run("alice", "bot"):
        for _ in range(2):
            with pytest.raises(ActionDenied) as err:
                ledger.execute(drop, {"sql": "select 1"}, lambda sql: None)
            assert err.value.rule_id == "no-drops"


def test_a_cancelled_action_is_rejected_when_called_again(ledger: Ledger) -> None:
    payout = ToolSpec(name="payments.payout", effect="financial")
    with ledger.run("alice", "bot"):
        with pytest.raises(ActionScheduled) as err:
            ledger.execute(payout, ARGS, lambda **kw: None)
        ledger.cancel(err.value.intent_id)
        with pytest.raises(ApprovalRejected, match="cancelled"):
            ledger.execute(payout, ARGS, lambda **kw: None)


def test_the_same_key_with_other_arguments_is_refused(ledger: Ledger) -> None:
    with ledger.run("alice", "bot"):
        ledger.execute(REFUND, ARGS, lambda **kw: "ok", idempotency_key="k1")
        with pytest.raises(IntentError, match="different arguments"):
            ledger.execute(REFUND, {**ARGS, "amount": 6}, lambda **kw: "ok", idempotency_key="k1")


def test_an_approved_action_whose_worker_stopped_runs_on_the_next_call(ledger: Ledger) -> None:
    calls: list[int] = []
    with ledger.run("alice", "bot", run_id="r1"):
        crash_at(ledger, "after_decision_commit", REFUND, ARGS)
        ledger.execute(REFUND, ARGS, lambda **kw: calls.append(1))
    assert calls == [1]


def test_a_missing_run_record_fails_closed(ledger: Ledger) -> None:
    with ledger.run("alice", "bot", run_id="ghost", resume=True), pytest.raises(LedgerUnavailable):
        ledger.execute(REFUND, ARGS, lambda **kw: None)


def test_a_run_that_cannot_be_recorded_fails_closed(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: Transaction, *args: object, **kwargs: object) -> None:
        raise StorageError("disk full")

    monkeypatch.setattr(Transaction, "insert_run", broken)
    with pytest.raises(LedgerUnavailable), ledger.run("alice", "bot"):
        pass  # pragma: no cover, the run never starts


def test_credentials_without_a_provider_fail_closed(ledger: Ledger) -> None:
    spec = ToolSpec(name="payments.refund", effect="financial", credentials=("stripe",))
    calls: list[int] = []
    with ledger.run("alice", "bot"), pytest.raises(LedgerUnavailable, match="no provider"):
        ledger.execute(spec, ARGS, lambda **kw: calls.append(1))
    assert calls == []


def test_an_async_tool_called_synchronously_is_a_clear_failure(ledger: Ledger) -> None:
    async def tool(order_id: str, amount: float) -> object:
        return "never"  # pragma: no cover, never awaited

    with ledger.run("alice", "bot"), pytest.raises(TypeError, match="aexecute"):
        ledger.execute(REFUND, ARGS, tool)


def test_aexecute_recovers_through_a_probe(tmp_path: Path) -> None:
    from bench.fakes.payments import FakePayments  # noqa: PLC0415

    service = FakePayments(native=False)
    spec = ToolSpec(name="payments.refund", effect="financial", idempotency="probe",
                    probe="bench.fakes.probes:find_refund")  # fmt: skip
    try:
        with Ledger.open(tmp_path / "l.db", POLICY, key=KEY, lease_ttl=0) as led:
            led.probe_context["payments"] = service
            with led.run("alice", "bot", run_id="r1"):
                crash_at(led, "after_executing_commit", spec, ARGS)
                handle = current_run()
                assert handle is not None
                service.refund("o1", 5, idempotency_key=handle.last_idempotency_key)

                async def go() -> object:
                    return await led.aexecute(spec, ARGS, lambda **kw: None)

                found = asyncio.run(go())
        assert found == {"refund_id": "re_000001", "order_id": "o1", "amount": 5.0}
        assert service.count() == 1
    finally:
        service.close()


def test_the_scheduler_reports_an_action_it_cannot_settle(ledger: Ledger) -> None:
    payout = ToolSpec(name="payments.payout", effect="financial")
    with ledger.run("alice", "bot", run_id="r1"), pytest.raises(ActionScheduled):
        ledger.execute(payout, ARGS, lambda **kw: None)
    time.sleep(1.05)
    ledger.on_step = lambda step: (
        (_ for _ in ()).throw(_Crash) if step == "after_side_effect" else None
    )
    with pytest.raises(_Crash):
        ledger.run_due({payout.name: (payout, lambda **kw: None)})
    ledger.on_step = None
    report = ledger.run_due({payout.name: (payout, lambda **kw: None)})
    assert [(r.state, r.action) for r in report] == [
        (IntentState.UNKNOWN, "stopped: unknown_outcome")
    ]


def test_counters_read_lazily(ledger: Ledger) -> None:
    with ledger._storage().transaction() as tx:
        counters = _Counters(tx)
        assert (list(counters), len(counters), counters.get("nothing", 0.0)) == ([], 0, 0.0)


def test_scrub_handles_bytes_sets_slots_and_notes() -> None:
    secret = ("tok_", "abcdef123456")
    token = "".join(secret)

    class Slotted:
        __slots__ = ("key", "unset")

        def __init__(self) -> None:
            self.key = token

    assert token.encode() not in _scrub(token.encode() + b"!", (token,))  # type: ignore[operator]
    assert token not in repr(_scrub(Slotted(), (token,)))
    assert token not in repr(_scrub([{token}], (token,)))


def test_error_notes_are_scrubbed(tmp_path: Path) -> None:
    spec = ToolSpec(name="payments.refund", effect="financial", credentials=("stripe",))
    token = "tok_" + "notes_" + "1a2b3c"
    creds = EnvCredentials(environ={"ARBITR_CRED_STRIPE": token})

    def tool(order_id: str, amount: float, credentials: dict[str, str]) -> object:
        exc = ValueError("declined")
        exc.add_note(f"while using {credentials['stripe']}")
        raise exc

    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY, credentials=creds) as led,
        led.run("alice", "bot"),
        pytest.raises(ValueError, match="declined") as err,
    ):
        led.execute(spec, ARGS, tool)
    assert token not in "".join(err.value.__notes__)


def test_an_unknown_outcome_is_still_reported_without_credentials(ledger: Ledger) -> None:
    def times_out(order_id: str, amount: float) -> object:
        raise TimeoutError("slow")

    with ledger.run("alice", "bot"), pytest.raises(UnknownOutcome) as err:
        ledger.execute(REFUND, ARGS, times_out)
    assert isinstance(err.value.__cause__, TimeoutError)
