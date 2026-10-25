"""The options deterministic simulation needs: a replaceable clock and no heartbeat thread."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from bench.fakes.payments import FakePayments

from arbitr.core.errors import ActionScheduled
from arbitr.core.redact import Redactor
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.executor import Ledger
from arbitr.policy.schema import load_policy
from arbitr.storage.sqlite import SQLiteStorage, format_db_time, parse_db_time

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"clock-heartbeat!" * 2
START = datetime(2030, 1, 1, tzinfo=UTC)
POLICY = load_policy("""
version: 1
default: { financial: allow }
rules:
  - id: hold-payouts
    when: { tool: payments.payout }
    then: delay 5s
    reason: Payouts wait so someone can cancel them.
""")
REFUND = ToolSpec(name="payments.refund", effect="financial", idempotency="native")
PAYOUT = ToolSpec(name="payments.payout", effect="financial", idempotency="native")


class FakeClock:
    """A clock that moves only when told to."""

    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def payments() -> Iterator[FakePayments]:
    service = FakePayments()
    yield service
    service.close()


def refund_fn(service: FakePayments) -> Any:
    def call(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
        return service.refund(order_id, amount, idempotency_key=idempotency_key)

    return call


def test_storage_uses_the_given_clock(tmp_path: Path) -> None:
    clock = FakeClock()
    with SQLiteStorage.open(tmp_path / "l.db", Redactor(KEY), clock=clock) as db:
        with db.transaction() as tx:
            assert tx.now == "2030-01-01T00:00:00.000Z"
            tx.insert_run("r", "alice", "bot")
        clock.advance(1.25)
        with db.transaction() as tx:
            assert tx.now == "2030-01-01T00:00:01.250Z"
        assert [e.created_at for e in db.events()] == ["2030-01-01T00:00:00.000Z"]


def test_storage_without_a_clock_uses_the_database_clock(tmp_path: Path) -> None:
    with (
        SQLiteStorage.open(tmp_path / "l.db", Redactor(KEY)) as db,
        db.transaction() as tx,
    ):
        drift = abs(parse_db_time(tx.now) - datetime.now(UTC))
    assert drift < timedelta(seconds=60)


def test_leases_expire_on_the_given_clock(tmp_path: Path, payments: FakePayments) -> None:
    clock = FakeClock()
    path = tmp_path / "l.db"
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=10, clock=clock) as led:
        seen: list[int] = []

        def tool(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
            clock.advance(9)
            seen.append(led.stale_count())
            clock.advance(2)
            seen.append(led.stale_count())
            return {"ok": True}

        with led.run("alice", "bot"):
            led.execute(REFUND, {"order_id": "o1", "amount": 1}, tool)
        assert seen == [0, 1]
        assert led.verify().ok


def test_a_cancel_window_follows_the_given_clock(tmp_path: Path, payments: FakePayments) -> None:
    clock = FakeClock()
    tools = {PAYOUT.name: (PAYOUT, refund_fn(payments))}
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY, worker_id="w1", clock=clock) as led:
        with led.run("alice", "bot", run_id="r1"), pytest.raises(ActionScheduled) as err:
            led.execute(PAYOUT, {"order_id": "o1", "amount": 5}, refund_fn(payments))
        row = led.intent(err.value.intent_id)
        assert row is not None
        assert row.scheduled_for == format_db_time(START + timedelta(seconds=5))
        clock.advance(4.9)
        assert led.run_due(tools) == []
        clock.advance(0.2)
        assert [r.state for r in led.run_due(tools)] == [IntentState.SUCCEEDED]
        assert payments.count() == 1


def test_heartbeat_false_never_extends_a_lease(tmp_path: Path, payments: FakePayments) -> None:
    path = tmp_path / "l.db"
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=0.15, heartbeat=False) as led:

        def slow(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
            time.sleep(0.4)
            return "done"

        with led.run("alice", "bot"):
            assert led.execute(REFUND, {"order_id": "o1", "amount": 1}, slow) == "done"
        with SQLiteStorage.open(path, Redactor(KEY)) as db:
            kinds = [e.kind for e in db.events()]
    assert "lease_extended" not in kinds
    assert "succeeded" in kinds


def test_heartbeat_is_on_by_default(tmp_path: Path) -> None:
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY) as led:
        assert led.heartbeat is True
        assert led.clock is None
