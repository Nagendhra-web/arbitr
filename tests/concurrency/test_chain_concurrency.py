"""Many writers on one ledger: the audit chain never forks and keys stay unique."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from arbitr.core.errors import StaleStateError
from arbitr.core.intent import build_intent
from arbitr.core.redact import Redactor
from arbitr.core.spec import ToolSpec
from arbitr.storage.sqlite import SQLiteStorage

if TYPE_CHECKING:
    from pathlib import Path

KEY = b"concurrency-key!" * 2
SPEC = ToolSpec(name="payments.refund", effect="financial")


def test_parallel_writers_keep_one_unbroken_chain(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with SQLiteStorage.open(path, Redactor(KEY)) as db, db.transaction() as tx:
        tx.insert_run("r", "alice", "bot")

    def writer(w: int) -> int:
        with SQLiteStorage.open(path, Redactor(KEY), busy_timeout_ms=30_000) as db:
            for i in range(25):
                with db.transaction() as tx:
                    tx.append_event("note", {"w": w, "i": i})
        return w

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(writer, range(8)))

    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        result = db.verify()
        assert result.ok, result.describe()
        assert result.checked == 1 + 8 * 25


def test_racing_inserts_of_one_key_store_exactly_one_intent(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with SQLiteStorage.open(path, Redactor(KEY)) as db, db.transaction() as tx:
        tx.insert_run("r", "alice", "bot")

    def attempt(_: int) -> bool:
        intent = build_intent(SPEC, {"order": "o1", "amount": 5}, run_id="r", principal="alice")
        with SQLiteStorage.open(path, Redactor(KEY), busy_timeout_ms=30_000) as db:
            try:
                with db.transaction() as tx:
                    tx.insert_intent(intent)
            except StaleStateError:
                return False
        return True

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(50)))

    assert results.count(True) == 1
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        assert db.intent_count() == 1
        assert db.verify().ok
