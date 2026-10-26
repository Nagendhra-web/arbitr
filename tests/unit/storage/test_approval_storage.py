"""Approvals in storage: binding, expiry, quorum, roles, and votes on the audit chain."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import ApprovalError
from arbitr.core.intent import build_intent
from arbitr.core.redact import Redactor
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.policy.engine import BudgetCharge
from arbitr.storage.migrations import SQLITE
from arbitr.storage.sqlite import SQLiteStorage

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"approval-storage" * 2
SPEC = ToolSpec(name="payments.refund", effect="financial")
S = IntentState


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SQLiteStorage]:
    with SQLiteStorage.open(tmp_path / "ledger.db", Redactor(KEY)) as storage:
        with storage.transaction() as tx:
            tx.insert_run("r", "alice", "bot")
        yield storage


def pending(db: SQLiteStorage, *, ttl: float = 60, **approval: object) -> tuple[str, str, str]:
    """An intent waiting for approval. Returns (intent_id, intent_hash, approval_id)."""
    intent = build_intent(SPEC, {"order": "o1", "amount": 500}, run_id="r", principal="alice")
    with db.transaction() as tx:
        tx.insert_intent(intent)
        tx.transition(intent.intent_id, S.PENDING_APPROVAL, expected=S.PROPOSED)
        tx.reserve_all(
            [BudgetCharge("cap", "rule:cap|run:r", 500, 1000)], intent_id=intent.intent_id
        )
        row = tx.create_approval(intent.intent_id, ttl_seconds=ttl, **approval)  # type: ignore[arg-type]
    return intent.intent_id, intent.intent_hash, row.approval_id


def state(db: SQLiteStorage, intent_id: str) -> IntentState:
    with db.transaction() as tx:
        row = tx.get_intent(intent_id)
    assert row is not None
    return row.state


def test_schema_version_is_current(db: SQLiteStorage) -> None:
    assert db.schema_version() == len(SQLITE) == 6


def test_one_approval_moves_the_intent_to_approved(db: SQLiteStorage) -> None:
    intent_id, intent_hash, approval_id = pending(db)
    with db.transaction() as tx:
        result = tx.vote(approval_id, approver="bob", roles=(), decision="approve",
                         intent_hash=intent_hash)  # fmt: skip
    assert result.status == "approved"
    assert state(db, intent_id) == S.APPROVED
    assert db.verify().ok


def test_an_approval_cannot_authorize_other_arguments(db: SQLiteStorage) -> None:
    _, _, approval_id = pending(db)
    other = build_intent(SPEC, {"order": "o1", "amount": 9000}, run_id="r", principal="alice")
    with pytest.raises(ApprovalError, match="different arguments"), db.transaction() as tx:
        tx.vote(approval_id, approver="bob", roles=(), decision="approve",
                intent_hash=other.intent_hash)  # fmt: skip


def test_an_expired_approval_is_rejected_and_releases_the_budget(db: SQLiteStorage) -> None:
    intent_id, intent_hash, approval_id = pending(db, ttl=0.01)
    time.sleep(0.05)
    with db.transaction() as tx:
        result = tx.vote(approval_id, approver="bob", roles=(), decision="approve",
                         intent_hash=intent_hash)  # fmt: skip
    assert result.status == "expired"
    assert state(db, intent_id) == S.EXPIRED
    with db.transaction() as tx:
        assert tx.budget_counters(["rule:cap|run:r"]) == {"rule:cap|run:r": 0.0}
    assert db.verify().ok


def test_expire_approvals_sweeps_everything_past_its_time(db: SQLiteStorage) -> None:
    intent_id, _, approval_id = pending(db, ttl=0.01)
    time.sleep(0.05)
    with db.transaction() as tx:
        swept = tx.expire_approvals()
    assert [a.approval_id for a in swept] == [approval_id]
    assert state(db, intent_id) == S.EXPIRED


def test_a_rejection_rejects_the_intent(db: SQLiteStorage) -> None:
    intent_id, intent_hash, approval_id = pending(db, required=2)
    with db.transaction() as tx:
        result = tx.vote(approval_id, approver="bob", roles=(), decision="reject",
                         intent_hash=intent_hash, note="wrong customer")  # fmt: skip
    assert result.status == "rejected"
    assert state(db, intent_id) == S.REJECTED
    with db.transaction() as tx:
        assert tx.budget_counters(["rule:cap|run:r"]) == {"rule:cap|run:r": 0.0}
        assert [v.note for v in tx.approval_votes(approval_id)] == ["wrong customer"]


def test_two_person_rule(db: SQLiteStorage) -> None:
    intent_id, intent_hash, approval_id = pending(db, required=2, roles=("sre",))
    with db.transaction() as tx:
        first = tx.vote(approval_id, approver="bob", roles=("sre",), decision="approve",
                        intent_hash=intent_hash)  # fmt: skip
    assert first.status == "pending"
    assert state(db, intent_id) == S.PENDING_APPROVAL
    with pytest.raises(ApprovalError, match="already voted"), db.transaction() as tx:
        tx.vote(approval_id, approver="bob", roles=("sre",), decision="approve",
                intent_hash=intent_hash)  # fmt: skip
    with pytest.raises(ApprovalError, match="role"), db.transaction() as tx:
        tx.vote(approval_id, approver="eve", roles=("dev",), decision="approve",
                intent_hash=intent_hash)  # fmt: skip
    with db.transaction() as tx:
        second = tx.vote(approval_id, approver="carol", roles=("sre", "dev"), decision="approve",
                         intent_hash=intent_hash)  # fmt: skip
    assert second.status == "approved"
    assert state(db, intent_id) == S.APPROVED
    assert db.verify().ok


def test_the_principal_cannot_approve_their_own_action(db: SQLiteStorage) -> None:
    _, intent_hash, approval_id = pending(db, separate_from="alice")
    with pytest.raises(ApprovalError, match="own action"), db.transaction() as tx:
        tx.vote(approval_id, approver="alice", roles=(), decision="approve",
                intent_hash=intent_hash)  # fmt: skip


def test_a_decided_approval_takes_no_more_votes(db: SQLiteStorage) -> None:
    _, intent_hash, approval_id = pending(db)
    with db.transaction() as tx:
        tx.vote(approval_id, approver="bob", roles=(), decision="approve", intent_hash=intent_hash)
    with pytest.raises(ApprovalError, match="already approved"), db.transaction() as tx:
        tx.vote(approval_id, approver="carol", roles=(), decision="reject",
                intent_hash=intent_hash)  # fmt: skip


def test_quorum_holds_under_concurrent_votes(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        with db.transaction() as tx:
            tx.insert_run("r", "alice", "bot")
        _, intent_hash, approval_id = pending(db, required=3)
    statuses: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def voter(name: str) -> None:
        with SQLiteStorage.open(path, Redactor(KEY), busy_timeout_ms=30_000) as mine:
            barrier.wait()
            try:
                with mine.transaction() as tx:
                    result = tx.vote(approval_id, approver=name, roles=(), decision="approve",
                                     intent_hash=intent_hash)  # fmt: skip
                outcome = result.status
            except ApprovalError:
                outcome = "refused"
        with lock:
            statuses.append(outcome)

    threads = [threading.Thread(target=voter, args=(f"v{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert statuses.count("pending") == 2
    assert statuses.count("approved") == 1
    assert statuses.count("refused") == 5
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        with db.transaction() as tx:
            assert len(tx.approval_votes(approval_id)) == 3
        assert db.verify().ok


def test_a_vote_changed_without_its_event_is_caught(db: SQLiteStorage) -> None:
    _, intent_hash, approval_id = pending(db, required=2)
    with db.transaction() as tx:
        tx.vote(approval_id, approver="bob", roles=(), decision="approve", intent_hash=intent_hash)
    db._conn.execute("UPDATE approval_votes SET approver = 'mallory'")
    report = db.verify()
    assert not report.ok
    assert "vote" in (report.reason or "")


def test_an_approval_status_changed_without_its_event_is_caught(db: SQLiteStorage) -> None:
    _, _, approval_id = pending(db)
    db._conn.execute("UPDATE approvals SET status = 'approved'")
    report = db.verify()
    assert not report.ok
    assert approval_id in (report.reason or "")


def test_notes_are_redacted(db: SQLiteStorage) -> None:
    _, intent_hash, approval_id = pending(db)
    card = "4111111111111111"
    with db.transaction() as tx:
        tx.vote(approval_id, approver="bob", roles=(), decision="reject",
                intent_hash=intent_hash, note=f"card {card} is stolen")  # fmt: skip
    assert card not in "\n".join(db._conn.iterdump())
