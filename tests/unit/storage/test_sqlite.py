"""SQLite storage: schema, transactions, state changes and the audit chain."""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING

import pytest

from arbitr.core.audit import event_hash, export_jsonl
from arbitr.core.errors import IllegalTransitionError, StaleStateError, StorageError
from arbitr.core.intent import build_intent
from arbitr.core.redact import MARKER_PREFIX, Redactor
from arbitr.core.spec import ResourceRef, ToolSpec
from arbitr.core.states import IntentState
from arbitr.storage.migrations import SQLITE, Migration
from arbitr.storage.sqlite import SQLiteStorage, decode_args

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from arbitr.core.intent import ActionIntent

KEY = b"storage-test-key" * 2
REFUND = ToolSpec(name="payments.refund", effect="financial", redact=["$.card"])
S = IntentState


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SQLiteStorage]:
    with SQLiteStorage.open(tmp_path / "ledger.db", Redactor(KEY)) as storage:
        yield storage


def make_intent(n: int = 1, **args: object) -> ActionIntent:
    return build_intent(
        REFUND, {"order": f"o{n}", "amount": 10, **args}, run_id="r1", principal="alice"
    )


def seed_run(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.insert_run("r1", "alice", "support-bot")


# ---------------------------------------------------------------- schema


def test_fresh_database_is_migrated_with_durable_settings(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        assert db.schema_version() == len(SQLITE)
        assert len(db.install_id()) == 26
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "runs",
        "intents",
        "receipts",
        "approvals",
        "budget_counters",
        "events",
        "tool_pins",
        "meta",
        "schema_version",
    } <= tables
    conn.close()


def test_connection_uses_full_sync_and_foreign_keys(db: SQLiteStorage) -> None:
    conn = db._conn
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_reopening_keeps_install_id_and_applies_nothing(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        first = db.install_id()
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        assert db.install_id() == first
        assert db.migrate() == []


def test_new_migrations_apply_in_order(db: SQLiteStorage) -> None:
    extra = (
        Migration(4, "four", "CREATE TABLE t4 (x INTEGER)"),
        Migration(3, "three", "CREATE TABLE t3 (x INTEGER); CREATE TABLE t3b (y INTEGER)"),
    )

    assert db.migrate((*SQLITE, *extra)) == [3, 4]
    assert db.schema_version() == 4


def test_failed_migration_rolls_back(db: SQLiteStorage) -> None:

    bad = Migration(3, "broken", "CREATE TABLE ok_table (x INTEGER); THIS IS NOT SQL")
    with pytest.raises(StorageError, match="migration 3"):
        db.migrate((*SQLITE, bad))
    assert db.schema_version() == len(SQLITE)
    names = {r[0] for r in db._conn.execute("SELECT name FROM sqlite_master")}
    assert "ok_table" not in names


def test_unopenable_path_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(StorageError, match="cannot open ledger"):
        SQLiteStorage.open(tmp_path / "missing-dir" / "x.db", Redactor(KEY))


# ---------------------------------------------------------------- intents


def test_insert_and_read_intent(db: SQLiteStorage) -> None:
    seed_run(db)
    intent = make_intent()
    with db.transaction() as tx:
        row = tx.insert_intent(intent)
    assert row.state == S.PROPOSED
    assert row.intent_hash == intent.intent_hash
    assert decode_args(row) == {"order": "o1", "amount": 10}
    with db.transaction() as tx:
        assert tx.get_intent(intent.intent_id) == row
        assert tx.get_intent_by_key(intent.idempotency_key) == row
        assert tx.get_intent("nope") is None


def test_duplicate_idempotency_key_is_refused(db: SQLiteStorage) -> None:
    seed_run(db)
    with db.transaction() as tx:
        tx.insert_intent(make_intent())
    with pytest.raises(StaleStateError, match="already exists"), db.transaction() as tx:
        tx.insert_intent(make_intent())  # same args, new intent id, same key
    assert db.intent_count() == 1


def test_intent_for_unknown_run_is_refused(db: SQLiteStorage) -> None:
    with pytest.raises(StorageError, match="could not record intent"), db.transaction() as tx:
        tx.insert_intent(make_intent())


def test_redact_paths_and_detection_apply_to_stored_args(db: SQLiteStorage) -> None:
    seed_run(db)
    secret = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    intent = make_intent(card="4111111111111111", memo=f"use {secret}")
    with db.transaction() as tx:
        row = tx.insert_intent(intent, REFUND.redact)
    stored = decode_args(row)
    assert isinstance(stored, dict)
    assert stored["card"].startswith(MARKER_PREFIX)
    assert secret not in row.args_redacted
    assert intent.args["card"] == "4111111111111111"  # the in-memory intent is untouched


def test_resources_are_stored(db: SQLiteStorage) -> None:
    seed_run(db)
    ref = ResourceRef(kind="database", uri="postgres://prod")
    intent = build_intent(REFUND, {}, run_id="r1", principal="alice", resources=(ref,))
    with db.transaction() as tx:
        row = tx.insert_intent(intent)
    assert json.loads(row.resources) == [
        {"kind": "database", "uri": "postgres://prod", "attrs": {}}
    ]


def test_error_inside_transaction_rolls_everything_back(db: SQLiteStorage) -> None:
    seed_run(db)

    def write_then_fail() -> None:
        with db.transaction() as tx:
            tx.insert_intent(make_intent())
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        write_then_fail()
    assert db.intent_count() == 0
    assert [e.kind for e in db.events()] == ["run_started"]


# ---------------------------------------------------------------- transitions


def test_full_lifecycle_records_one_event_per_step(db: SQLiteStorage) -> None:
    seed_run(db)
    intent = make_intent()
    with db.transaction() as tx:
        tx.insert_intent(intent)
        tx.transition(
            intent.intent_id,
            S.APPROVED,
            expected=S.PROPOSED,
            fields={"decision": "allow", "decision_rule": "default"},
        )
        tx.transition(
            intent.intent_id,
            S.EXECUTING,
            expected=S.APPROVED,
            fields={"attempt": 1, "lease_owner": "w1", "lease_expires_at": tx.now},
        )
        row = tx.transition(intent.intent_id, S.SUCCEEDED, expected=S.EXECUTING)
    assert row.state == S.SUCCEEDED
    assert (row.decision, row.attempt, row.lease_owner) == ("allow", 1, "w1")
    kinds = [e.kind for e in db.events()]
    assert kinds == ["run_started", "intent_created", "approved", "executing", "succeeded"]
    assert db.verify().ok


def test_illegal_transition_raises_and_changes_nothing(db: SQLiteStorage) -> None:
    seed_run(db)
    intent = make_intent()
    with db.transaction() as tx:
        tx.insert_intent(intent)
    with pytest.raises(IllegalTransitionError), db.transaction() as tx:
        tx.transition(intent.intent_id, S.SUCCEEDED, expected=S.PROPOSED)
    with db.transaction() as tx:
        row = tx.get_intent(intent.intent_id)
    assert row is not None
    assert row.state == S.PROPOSED


def test_transition_is_compare_and_set(db: SQLiteStorage) -> None:
    seed_run(db)
    intent = make_intent()
    with db.transaction() as tx:
        tx.insert_intent(intent)
        tx.transition(intent.intent_id, S.DENIED, expected=S.PROPOSED)
    with pytest.raises(StaleStateError, match="not in state PROPOSED"), db.transaction() as tx:
        tx.transition(intent.intent_id, S.APPROVED, expected=S.PROPOSED)


def test_transition_of_missing_intent(db: SQLiteStorage) -> None:
    with pytest.raises(StaleStateError), db.transaction() as tx:
        tx.transition("ghost", S.APPROVED, expected=S.PROPOSED)


def test_only_listed_fields_can_be_updated(db: SQLiteStorage) -> None:
    seed_run(db)
    intent = make_intent()
    with db.transaction() as tx:
        tx.insert_intent(intent)
    with pytest.raises(StorageError, match="cannot be updated"), db.transaction() as tx:
        tx.transition(
            intent.intent_id, S.APPROVED, expected=S.PROPOSED, fields={"intent_hash": "forged"}
        )


def test_database_clock_is_used(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        assert tx.now.endswith("Z")
        assert tx.now[:4].isdigit()
        assert tx.now[10] == "T"


# ---------------------------------------------------------------- audit chain


def fill(db: SQLiteStorage, n: int) -> None:
    seed_run(db)
    for i in range(n):
        with db.transaction() as tx:
            tx.append_event("note", {"i": i})


def test_clean_chain_verifies(db: SQLiteStorage) -> None:
    fill(db, 50)
    result = db.verify()
    assert result.ok
    assert result.checked == 51
    assert "51 events" in result.describe()


def tamper(db: SQLiteStorage, sql: str, params: tuple[object, ...] = ()) -> None:
    db._conn.execute(sql, params)


@pytest.mark.parametrize(
    ("sql", "broken", "reason"),
    [
        ("UPDATE events SET payload = '{\"i\":99}' WHERE seq = 5", 5, "contents"),
        ("UPDATE events SET kind = 'forged' WHERE seq = 5", 5, "contents"),
        ("UPDATE events SET created_at = '2000-01-01T00:00:00.000Z' WHERE seq = 5", 5, "contents"),
        ("DELETE FROM events WHERE seq = 5", 6, "does not link"),
        ("UPDATE events SET prev_hash = 'x' WHERE seq = 1", 1, "does not link"),
    ],
)
def test_tampering_is_caught(db: SQLiteStorage, sql: str, broken: int, reason: str) -> None:
    fill(db, 10)
    tamper(db, sql)
    result = db.verify()
    assert not result.ok
    assert result.broken_seq == broken
    assert reason in (result.reason or "")
    assert f"broken at event {broken}" in result.describe()


def test_recomputed_hash_with_wrong_link_is_caught(db: SQLiteStorage) -> None:
    """An attacker who rewrites one event and fixes its own hash still breaks the next link."""

    fill(db, 10)
    e5 = next(e for e in db.events() if e.seq == 5)
    forged = '{"i":"forged"}'
    new_hash = event_hash(
        e5.prev_hash, e5.kind, forged, e5.created_at, intent_id=e5.intent_id, run_id=e5.run_id
    )
    tamper(db, "UPDATE events SET payload = ?, hash = ? WHERE seq = 5", (forged, new_hash))
    result = db.verify()
    assert (result.ok, result.broken_seq) == (False, 6)


def test_genesis_is_bound_to_the_install(tmp_path: Path) -> None:
    """A chain copied into another install does not verify there."""
    a = SQLiteStorage.open(tmp_path / "a.db", Redactor(KEY))
    fill(a, 3)
    a.close()
    b = SQLiteStorage.open(tmp_path / "a.db", Redactor(KEY))
    b._genesis = "0" * 64
    assert not b.verify().ok
    b.close()


def test_export_jsonl(db: SQLiteStorage) -> None:
    fill(db, 2)
    lines = list(export_jsonl(db.events()))
    assert len(lines) == 3
    first = json.loads(lines[0])
    assert first["kind"] == "run_started"
    assert set(first) == {
        "seq",
        "intent_id",
        "run_id",
        "kind",
        "payload",
        "prev_hash",
        "hash",
        "created_at",
    }


def test_events_after_seq(db: SQLiteStorage) -> None:
    fill(db, 4)
    assert [e.seq for e in db.events(after_seq=3)] == [4, 5]


def test_event_payloads_are_redacted(db: SQLiteStorage) -> None:
    seed_run(db)
    secret = "ghp_" + "Z" * 36
    with db.transaction() as tx:
        tx.append_event("note", {"text": f"token {secret}"})
    assert all(secret not in e.payload for e in db.events())
