"""Storage for execution: leases, heartbeats, receipts, approvals and schedules."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import StaleStateError, StorageError
from arbitr.core.intent import build_intent
from arbitr.core.redact import Redactor
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.policy.engine import BudgetCharge
from arbitr.storage.migrations import SQLITE
from arbitr.storage.sqlite import SQLiteStorage, parse_db_time

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"execution-store!" * 2
SPEC = ToolSpec(name="payments.refund", effect="financial")
S = IntentState


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SQLiteStorage]:
    with SQLiteStorage.open(tmp_path / "ledger.db", Redactor(KEY)) as storage:
        with storage.transaction() as tx:
            tx.insert_run("r", "alice", "bot")
        yield storage


def approved(db: SQLiteStorage, args: dict[str, object] | None = None) -> str:
    intent = build_intent(SPEC, args or {"order": "o1", "amount": 5}, run_id="r", principal="alice")
    with db.transaction() as tx:
        tx.insert_intent(intent)
        tx.transition(
            intent.intent_id, S.APPROVED, expected=S.PROPOSED, fields={"decision": "allow"}
        )
    return intent.intent_id


def test_schema_version_is_current(db: SQLiteStorage) -> None:
    assert db.schema_version() == len(SQLITE)


def test_args_exact_tells_whether_stored_args_are_the_real_ones(db: SQLiteStorage) -> None:
    plain = build_intent(SPEC, {"order": "o1"}, run_id="r", principal="alice")
    fake = "Zq7pw-" + "abc" + "def123"  # built from pieces so secret scanners stay quiet
    secret = build_intent(SPEC, {"order": "o2", "api_key": fake}, run_id="r", principal="alice")
    with db.transaction() as tx:
        assert tx.insert_intent(plain).args_exact
        assert not tx.insert_intent(secret).args_exact


def test_start_execution_takes_a_lease_on_the_database_clock(db: SQLiteStorage) -> None:
    intent_id = approved(db)
    with db.transaction() as tx:
        row = tx.start_execution(intent_id, expected=S.APPROVED, worker="w1", ttl_seconds=30)
        now = parse_db_time(tx.now)
    assert (row.state, row.attempt, row.lease_owner) == (S.EXECUTING, 1, "w1")
    assert row.lease_expires_at is not None
    assert parse_db_time(row.lease_expires_at) - now == timedelta(seconds=30)
    assert db.verify().ok


def test_heartbeat_extends_only_the_owners_lease(db: SQLiteStorage) -> None:
    intent_id = approved(db)
    with db.transaction() as tx:
        row = tx.start_execution(intent_id, expected=S.APPROVED, worker="w1", ttl_seconds=5)
    with db.transaction() as tx:
        extended = tx.heartbeat(intent_id, worker="w1", attempt=1, ttl_seconds=60)
    assert extended.lease_expires_at is not None
    assert row.lease_expires_at is not None
    assert parse_db_time(extended.lease_expires_at) > parse_db_time(row.lease_expires_at)
    with pytest.raises(StaleStateError), db.transaction() as tx:
        tx.heartbeat(intent_id, worker="w2", attempt=1, ttl_seconds=60)
    with pytest.raises(StaleStateError), db.transaction() as tx:
        tx.heartbeat(intent_id, worker="w1", attempt=2, ttl_seconds=60)
    assert db.verify().ok


def test_a_lease_change_without_its_event_is_caught(db: SQLiteStorage, tmp_path: Path) -> None:
    intent_id = approved(db)
    with db.transaction() as tx:
        tx.start_execution(intent_id, expected=S.APPROVED, worker="w1", ttl_seconds=5)
    db._conn.execute(  # tamper outside the API
        "UPDATE intents SET lease_expires_at = '2099-01-01T00:00:00.000Z' WHERE intent_id = ?",
        (intent_id,),
    )
    assert not db.verify().ok


def test_stale_executions_are_found(db: SQLiteStorage) -> None:
    live = approved(db, {"order": "live"})
    stale = approved(db, {"order": "stale"})
    with db.transaction() as tx:
        tx.start_execution(live, expected=S.APPROVED, worker="w1", ttl_seconds=600)
        tx.start_execution(stale, expected=S.APPROVED, worker="w1", ttl_seconds=0)
    with db.transaction() as tx:
        assert [r.intent_id for r in tx.stale_executions()] == [stale]


def test_receipts_are_recorded_once_and_verified(db: SQLiteStorage) -> None:
    intent_id = approved(db)
    with db.transaction() as tx:
        tx.start_execution(intent_id, expected=S.APPROVED, worker="w1", ttl_seconds=30)
        receipt = tx.insert_receipt(
            intent_id,
            result={"refund_id": "re_1", "token": "Zq7pw-sk-secretvalue"},
            external_id="re_1",
            source="executed",
        )
    assert receipt.external_id == "re_1"
    assert "secretvalue" not in (receipt.result_redacted or "")
    with db.transaction() as tx:
        assert tx.get_receipt(intent_id) == receipt
    with pytest.raises(StaleStateError), db.transaction() as tx:
        tx.insert_receipt(intent_id, result=None, external_id=None, source="executed")
    assert db.verify().ok
    db._conn.execute("UPDATE receipts SET result_hash = 'x' WHERE intent_id = ?", (intent_id,))
    assert not db.verify().ok


def test_unencodable_results_still_get_a_receipt(db: SQLiteStorage) -> None:
    intent_id = approved(db)
    with db.transaction() as tx:
        receipt = tx.insert_receipt(intent_id, result=object(), external_id=None, source="executed")
    assert receipt.result_redacted is None
    assert len(receipt.result_hash) == 64


def test_big_results_are_cut(db: SQLiteStorage) -> None:
    intent_id = approved(db)
    with db.transaction() as tx:
        receipt = tx.insert_receipt(
            intent_id, result="x" * 200_000, external_id=None, source="executed"
        )
    assert receipt.result_redacted is None or len(receipt.result_redacted) <= 65_536


def test_approvals_are_bound_to_the_intent_hash(db: SQLiteStorage) -> None:
    intent = build_intent(SPEC, {"order": "o9", "amount": 500}, run_id="r", principal="alice")
    with db.transaction() as tx:
        tx.insert_intent(intent)
        tx.transition(intent.intent_id, S.PENDING_APPROVAL, expected=S.PROPOSED)
        approval = tx.create_approval(intent.intent_id, ttl_seconds=900)
        assert tx.get_approval(approval.approval_id) == approval
        assert tx.approval_for_intent(intent.intent_id) == approval
    assert (approval.status, approval.intent_hash) == ("pending", intent.intent_hash)
    assert db.verify().ok


def test_scheduled_intents_become_due(db: SQLiteStorage) -> None:
    soon = approved(db, {"order": "soon"})
    later = approved(db, {"order": "later"})
    with db.transaction() as tx:
        tx.schedule(soon, delay_seconds=0)
        tx.schedule(later, delay_seconds=3600)
        due = [r.intent_id for r in tx.due_scheduled()]
        assert due == [soon]
        assert tx.get_intent(later).state == S.SCHEDULED  # type: ignore[union-attr]
    assert db.verify().ok


def test_db_times_parse_to_utc() -> None:
    assert parse_db_time("2026-10-25T12:00:00.250Z") == datetime(
        2026, 10, 25, 12, 0, 0, 250_000, tzinfo=UTC
    )
    with pytest.raises(StorageError):
        parse_db_time("yesterday")


def test_reservations_are_kept_per_intent_and_released_together(db: SQLiteStorage) -> None:
    one, two = approved(db), approved(db, {"order": "o2", "amount": 7})
    cap = BudgetCharge("cap", "rule:cap|run:r", 5, 20)
    spend = BudgetCharge("scope", "scope-spend|run:r", 5, 20)
    with db.transaction() as tx:
        assert tx.reserve_all([cap, spend], intent_id=one)
        assert tx.reserve_all([BudgetCharge("cap", "rule:cap|run:r", 7, 20)], intent_id=two)
        assert tx.reservations(one) == {"rule:cap|run:r": 5.0, "scope-spend|run:r": 5.0}
    with db.transaction() as tx:
        assert tx.release_reservations(one) == 2
        assert tx.reservations(one) == {}
        assert tx.release_reservations(one) == 0  # releasing twice changes nothing
        counters = tx.budget_counters(["rule:cap|run:r", "scope-spend|run:r"])
    assert counters == {"rule:cap|run:r": 7.0, "scope-spend|run:r": 0.0}
    assert db.verify().ok


def test_a_reservation_changed_without_its_event_is_caught(
    db: SQLiteStorage, tmp_path: Path
) -> None:
    intent_id = approved(db)
    with db.transaction() as tx:
        tx.reserve_all([BudgetCharge("cap", "rule:cap|run:r", 5, 20)], intent_id=intent_id)
    db._conn.execute("UPDATE reservations SET amount = 1")
    report = db.verify()
    assert not report.ok
    assert "reservation" in (report.reason or "")
