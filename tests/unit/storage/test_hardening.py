"""Storage hardening: redaction by construction, audit integrity, fencing,
failure handling and concurrent opening."""

from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import StaleStateError, StorageError
from arbitr.core.intent import build_intent
from arbitr.core.redact import Redactor
from arbitr.core.spec import ResourceRef, ToolSpec
from arbitr.core.states import IntentState
from arbitr.storage.migrations import SQLITE, Migration
from arbitr.storage.sqlite import SQLiteStorage

if TYPE_CHECKING:
    from collections.abc import Iterator

KEY = b"storage-harden-k" * 2
S = IntentState
SPEC = ToolSpec(name="payments.refund", effect="financial", redact=["$.card"])
SECRET = "sk-ant-api03-" + "q" * 30


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SQLiteStorage]:
    with SQLiteStorage.open(tmp_path / "ledger.db", Redactor(KEY)) as storage:
        with storage.transaction() as tx:
            tx.insert_run("r1", "alice", "bot")
        yield storage


def raw(path: Path) -> bytes:
    return b"".join(
        Path(str(path) + s).read_bytes()
        for s in ("", "-wal", "-shm")
        if Path(str(path) + s).exists()
    )


# ---------------------------------------------------------------- redaction by construction


def test_spec_paths_apply_without_the_caller_passing_them(db: SQLiteStorage) -> None:
    intent = build_intent(SPEC, {"card": "plain-card-value"}, run_id="r1", principal="alice")
    with db.transaction() as tx:
        row = tx.insert_intent(intent)
    assert "plain-card-value" not in row.args_redacted


def test_resource_uris_and_attrs_are_redacted(db: SQLiteStorage, tmp_path: Path) -> None:
    ref = ResourceRef(
        kind="database",
        uri="postgres://admin:hunter2pass@prod/db",
        attrs={"password": "hunter2pass", "note": f"key {SECRET}"},
    )
    intent = build_intent(SPEC, {}, run_id="r1", principal="alice", resources=(ref,))
    with db.transaction() as tx:
        row = tx.insert_intent(intent)
    assert "hunter2pass" not in row.resources
    assert SECRET not in row.resources


def test_decision_reason_column_is_redacted(db: SQLiteStorage) -> None:
    intent = build_intent(SPEC, {}, run_id="r1", principal="alice")
    with db.transaction() as tx:
        tx.insert_intent(intent)
        row = tx.transition(
            intent.intent_id,
            S.DENIED,
            expected=S.PROPOSED,
            fields={"decision": "deny", "decision_reason": f"saw {SECRET} in args"},
        )
    assert SECRET not in (row.decision_reason or "")


@pytest.mark.parametrize("key", ["from", "to", "decision", "intent_id", "run_id"])
def test_detail_cannot_override_recorded_facts(db: SQLiteStorage, key: str) -> None:
    intent = build_intent(SPEC, {}, run_id="r1", principal="alice")
    with db.transaction() as tx:
        tx.insert_intent(intent)
    with pytest.raises(StorageError, match="detail"), db.transaction() as tx:
        tx.transition(
            intent.intent_id,
            S.APPROVED,
            expected=S.PROPOSED,
            fields={"decision": "allow"},
            detail={key: "forged"},
        )


# ---------------------------------------------------------------- audit integrity


def lifecycle(db: SQLiteStorage) -> str:
    intent = build_intent(SPEC, {"order": "o1"}, run_id="r1", principal="alice")
    with db.transaction() as tx:
        tx.insert_intent(intent)
        tx.transition(intent.intent_id, S.APPROVED, expected=S.PROPOSED)
        tx.transition(intent.intent_id, S.EXECUTING, expected=S.APPROVED, fields={"attempt": 1})
    return intent.intent_id


def test_moving_an_event_to_another_intent_is_caught(db: SQLiteStorage) -> None:
    lifecycle(db)
    db._conn.execute("UPDATE events SET intent_id = 'someone-else' WHERE kind = 'approved'")
    assert not db.verify().ok


def test_rewriting_run_id_on_an_event_is_caught(db: SQLiteStorage) -> None:
    lifecycle(db)
    db._conn.execute("UPDATE events SET run_id = 'r2' WHERE kind = 'executing'")
    assert not db.verify().ok


def test_direct_state_update_is_caught(db: SQLiteStorage) -> None:
    iid = lifecycle(db)
    db._conn.execute("UPDATE intents SET state = 'SUCCEEDED' WHERE intent_id = ?", (iid,))
    result = db.verify()
    assert not result.ok
    assert iid in (result.reason or "")


@pytest.mark.parametrize(
    ("column", "value"),
    [("intent_hash", "0" * 64), ("idempotency_key", "forged"), ("args_redacted", '{"order":"o2"}')],
)
def test_rewriting_intent_identity_is_caught(db: SQLiteStorage, column: str, value: str) -> None:
    iid = lifecycle(db)
    db._conn.execute(f"UPDATE intents SET {column} = ? WHERE intent_id = ?", (value, iid))  # noqa: S608
    assert not db.verify().ok


def test_intent_without_its_creation_event_is_caught(db: SQLiteStorage) -> None:
    lifecycle(db)
    db._conn.execute(
        "INSERT INTO intents (intent_id, run_id, tool, args_redacted, intent_hash,"
        " idempotency_key, effect, state, created_at, updated_at)"
        " VALUES ('ghost', 'r1', 't', '{}', 'h', 'k', 'write', 'APPROVED', 'x', 'x')"
    )
    assert not db.verify().ok


def test_clean_lifecycle_still_verifies(db: SQLiteStorage) -> None:
    lifecycle(db)
    assert db.verify().ok


# ---------------------------------------------------------------- fencing


def test_stale_attempt_cannot_finish(db: SQLiteStorage) -> None:
    iid = lifecycle(db)  # EXECUTING, attempt 1
    with db.transaction() as tx:
        tx.transition(iid, S.UNKNOWN, expected=S.EXECUTING, expected_attempt=1)
        tx.transition(iid, S.EXECUTING, expected=S.UNKNOWN, fields={"attempt": 2})
    with pytest.raises(StaleStateError), db.transaction() as tx:
        tx.transition(iid, S.SUCCEEDED, expected=S.EXECUTING, expected_attempt=1)
    with db.transaction() as tx:
        row = tx.transition(iid, S.SUCCEEDED, expected=S.EXECUTING, expected_attempt=2)
    assert row.state == S.SUCCEEDED


def test_lease_owner_fence(db: SQLiteStorage) -> None:
    intent = build_intent(SPEC, {}, run_id="r1", principal="alice")
    with db.transaction() as tx:
        tx.insert_intent(intent)
        tx.transition(intent.intent_id, S.APPROVED, expected=S.PROPOSED)
        tx.transition(
            intent.intent_id,
            S.EXECUTING,
            expected=S.APPROVED,
            fields={"attempt": 1, "lease_owner": "w1"},
        )
    with pytest.raises(StaleStateError), db.transaction() as tx:
        tx.transition(
            intent.intent_id, S.SUCCEEDED, expected=S.EXECUTING, expected_lease_owner="w2"
        )


# ---------------------------------------------------------------- error contract


def test_sqlite_errors_become_storage_errors(db: SQLiteStorage) -> None:
    with pytest.raises(StorageError), db.transaction() as tx:
        tx.insert_run("r1", "alice", "bot")  # duplicate run id
    with pytest.raises(StorageError), db.transaction() as tx:
        tx.insert_run("r9", "alice", "bot", mode="yolo")


def test_transaction_is_dead_after_its_block(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        pass
    with pytest.raises(StorageError, match="closed"):
        tx.append_event("late", {})


def test_failed_migration_raises_storage_error(db: SQLiteStorage) -> None:
    bad = Migration(3, "broken", "CREATE TABLE ok_table (x INTEGER); THIS IS NOT SQL")
    with pytest.raises(StorageError, match="migration 3"):
        db.migrate((*SQLITE, bad))
    assert db.schema_version() == len(SQLITE)


def test_newer_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        db.migrate((*SQLITE, Migration(99, "future", "CREATE TABLE future (x INTEGER)")))
    with pytest.raises(StorageError, match="newer"):
        SQLiteStorage.open(path, Redactor(KEY))


# ---------------------------------------------------------------- concurrent open


def test_many_threads_open_one_fresh_file(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"

    def opener(_: int) -> str:
        with SQLiteStorage.open(path, Redactor(KEY), busy_timeout_ms=30_000) as db:
            return db.install_id()

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(opener, range(8)))
    assert len(set(ids)) == 1
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        rows = db._conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
        assert rows == len(SQLITE)


def test_many_processes_open_one_fresh_file(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    code = (
        "import sys\n"
        "from arbitr.core.redact import Redactor\n"
        "from arbitr.storage.sqlite import SQLiteStorage\n"
        "with SQLiteStorage.open(sys.argv[1], Redactor(b'storage-harden-k' * 2),"
        " busy_timeout_ms=30000) as db:\n"
        "    print(db.install_id())\n"
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        for _ in range(4)
    ]
    outs = [p.communicate(timeout=120) for p in procs]
    assert all(p.returncode == 0 for p in procs), [o[1].decode() for o in outs]
    assert len({o[0].strip() for o in outs}) == 1


# ---------------------------------------------------------------- races


def test_two_writers_race_one_transition(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with SQLiteStorage.open(path, Redactor(KEY)) as db, db.transaction() as tx:
        tx.insert_run("r1", "alice", "bot")
        intent = build_intent(SPEC, {}, run_id="r1", principal="alice")
        tx.insert_intent(intent)

    def approve(_: int) -> bool:
        with SQLiteStorage.open(path, Redactor(KEY), busy_timeout_ms=30_000) as db:
            try:
                with db.transaction() as tx:
                    tx.transition(intent.intent_id, S.APPROVED, expected=S.PROPOSED)
            except StaleStateError:
                return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        wins = list(pool.map(approve, range(16)))
    assert wins.count(True) == 1
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        assert db.verify().ok
        assert [e.kind for e in db.events()].count("approved") == 1


def test_events_payload_is_json(db: SQLiteStorage) -> None:
    lifecycle(db)
    for event in db.events():
        json.loads(event.payload)
