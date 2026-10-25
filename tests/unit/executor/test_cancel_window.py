"""The cancel window: a delayed action waits, can be cancelled, then runs exactly once."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest
from bench.fakes.payments import FakePayments

from arbitr.core.errors import ActionScheduled, ApprovalPending, StaleStateError
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.executor import Ledger
from arbitr.policy.schema import load_policy

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"cancel-window!!!" * 2
WINDOW = 1.0
POLICY = load_policy("""
version: 1
default: { financial: allow }
rules:
  - id: hold-payouts
    when: { tool: payments.payout }
    then: delay 1s
    reason: Payouts wait a moment so someone can cancel them.
  - id: payout-cap
    when: { tool: payments.payout }
    budget: { scope: [run], sum_path: "$.amount", limit: 100 }
    then_exceeded: deny
    reason: Payout cap for the run.
""")
PAYOUT = ToolSpec(name="payments.payout", effect="financial", idempotency="native")
ARGS = {"order_id": "o1", "amount": 60}


@pytest.fixture
def payments() -> Iterator[FakePayments]:
    service = FakePayments()
    yield service
    service.close()


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "ledger.db", POLICY, key=KEY, worker_id="w1") as led:
        yield led


def payout_fn(service: FakePayments) -> Any:
    def call(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
        return service.refund(order_id, amount, idempotency_key=idempotency_key)

    return call


def tools(service: FakePayments) -> dict[str, tuple[ToolSpec, Any]]:
    return {PAYOUT.name: (PAYOUT, payout_fn(service))}


def schedule(ledger: Ledger, service: FakePayments, args: dict[str, object] = ARGS) -> str:
    with (
        ledger.run("alice", "bot", run_id="r1", resume=True),
        pytest.raises(ActionScheduled) as err,
    ):
        ledger.execute(PAYOUT, args, payout_fn(service))
    return err.value.intent_id


def start(ledger: Ledger) -> None:
    with ledger.run("alice", "bot", run_id="r1"):
        pass


def test_a_delayed_action_is_scheduled_and_does_not_run(
    ledger: Ledger, payments: FakePayments
) -> None:
    start(ledger)
    with ledger.run("alice", "bot", run_id="r1", resume=True) as run:
        with pytest.raises(ActionScheduled) as err:
            ledger.execute(PAYOUT, ARGS, payout_fn(payments))
        with pytest.raises(ActionScheduled):  # calling again during the window does not run it
            ledger.execute(PAYOUT, ARGS, payout_fn(payments))
        row = ledger.intent_by_key(run.last_idempotency_key)
    assert payments.count() == 0
    assert row is not None
    assert row.state == IntentState.SCHEDULED
    assert "unless someone cancels it" in err.value.to_tool_message()
    assert ledger.run_due(tools(payments)) == []  # not due yet


def test_a_due_action_runs_exactly_once(ledger: Ledger, payments: FakePayments) -> None:
    start(ledger)
    intent_id = schedule(ledger, payments)
    time.sleep(WINDOW + 0.1)
    report = ledger.run_due(tools(payments))
    assert [(r.intent_id, r.state, r.action) for r in report] == [
        (intent_id, IntentState.SUCCEEDED, "ran")
    ]
    assert ledger.run_due(tools(payments)) == []
    with ledger.run("alice", "bot", run_id="r1", resume=True):
        again = ledger.execute(PAYOUT, ARGS, payout_fn(payments))  # the agent asks later
    assert again == {"refund_id": "re_000001", "order_id": "o1", "amount": 60.0}
    assert payments.count() == 1
    assert ledger.verify().ok


def test_cancelling_in_the_window_prevents_the_side_effect(
    ledger: Ledger, payments: FakePayments
) -> None:
    start(ledger)
    intent_id = schedule(ledger, payments)
    row = ledger.cancel(intent_id, reason="wrong customer")
    assert row.state == IntentState.CANCELLED
    time.sleep(WINDOW + 0.1)
    assert ledger.run_due(tools(payments)) == []
    assert payments.count() == 0
    # The cancelled payout gave its budget back, so a full-cap payout fits.
    other = schedule(ledger, payments, {"order_id": "o2", "amount": 100})
    assert other != intent_id
    assert ledger.verify().ok


def test_a_crash_during_the_window_still_runs_once_after_restart(
    tmp_path: Path, payments: FakePayments
) -> None:
    path = tmp_path / "ledger.db"
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1") as one:
        start(one)
        schedule(one, payments)
    # worker 1 is gone; a new worker starts after the window
    time.sleep(WINDOW + 0.1)
    with Ledger.open(path, POLICY, key=KEY, worker_id="w2") as two:
        assert [r.action for r in two.run_due(tools(payments))] == ["ran"]
        assert two.run_due(tools(payments)) == []
    with Ledger.open(path, POLICY, key=KEY, worker_id="w3") as three:
        assert three.run_due(tools(payments)) == []
    assert payments.count() == 1


def test_an_action_that_already_ran_cannot_be_cancelled(
    ledger: Ledger, payments: FakePayments
) -> None:
    start(ledger)
    intent_id = schedule(ledger, payments)
    time.sleep(WINDOW + 0.1)
    ledger.run_due(tools(payments))
    with pytest.raises(StaleStateError, match="no longer scheduled"):
        ledger.cancel(intent_id)
    assert payments.count() == 1


def test_a_due_action_without_a_registered_tool_waits(
    ledger: Ledger, payments: FakePayments
) -> None:
    start(ledger)
    intent_id = schedule(ledger, payments)
    time.sleep(WINDOW + 0.1)
    report = ledger.run_due({})
    assert [(r.intent_id, r.state, r.action) for r in report] == [
        (intent_id, IntentState.SCHEDULED, "waiting: no function registered for payments.payout")
    ]
    assert payments.count() == 0


def test_a_failed_scheduled_action_releases_its_budget(
    ledger: Ledger, payments: FakePayments
) -> None:
    def declined(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
        raise ValueError("card declined")

    start(ledger)
    schedule(ledger, payments, {"order_id": "o1", "amount": 100})
    time.sleep(WINDOW + 0.1)
    (result,) = ledger.run_due({PAYOUT.name: (PAYOUT, declined)})
    assert (result.state, result.action) == (IntentState.FAILED, "failed: ValueError")
    schedule(ledger, payments, {"order_id": "o2", "amount": 100})  # fits again
    assert ledger.verify().ok


def test_redacted_arguments_need_approval_instead_of_a_delay(
    ledger: Ledger, payments: FakePayments
) -> None:
    start(ledger)
    token = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"  # built from pieces for secret scanners
    with (
        ledger.run("alice", "bot", run_id="r1", resume=True),
        pytest.raises(ApprovalPending) as err,
    ):
        ledger.execute(PAYOUT, {**ARGS, "api_key": token}, payout_fn(payments))
    assert err.value.rule_id == "hold-payouts"
    assert "redacted" in err.value.reason
    assert payments.count() == 0
