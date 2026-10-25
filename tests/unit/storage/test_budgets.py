"""Budget counters: atomic reservations that can never overspend."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import StorageError
from arbitr.core.redact import Redactor
from arbitr.policy.engine import BudgetCharge
from arbitr.storage.sqlite import SQLiteStorage

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"budget-test-key!" * 2
K = "rule:cap|principal:alice|day:2026-10-25"


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SQLiteStorage]:
    with SQLiteStorage.open(tmp_path / "ledger.db", Redactor(KEY)) as storage:
        yield storage


def test_reserve_within_the_limit(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        assert tx.reserve_budget(K, 40, 100)
        assert tx.reserve_budget(K, 60, 100)
        assert tx.budget_counters([K]) == {K: 100.0}


def test_reserve_past_the_limit_is_refused_and_changes_nothing(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.reserve_budget(K, 90, 100)
        assert not tx.reserve_budget(K, 11, 100)
        assert tx.budget_counters([K]) == {K: 90.0}


def test_release_returns_the_amount(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.reserve_budget(K, 70, 100)
        tx.release_budget(K, 30)
        assert tx.budget_counters([K]) == {K: 40.0}


def test_release_never_goes_below_zero(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.reserve_budget(K, 10, 100)
    with pytest.raises(StorageError, match="more than"), db.transaction() as tx:
        tx.release_budget(K, 11)


@pytest.mark.parametrize("amount", [0, -1, float("nan"), float("inf")])
def test_bad_amounts_are_refused(db: SQLiteStorage, amount: float) -> None:
    with pytest.raises(StorageError, match="amount"), db.transaction() as tx:
        tx.reserve_budget(K, amount, 100)


def test_unknown_keys_read_as_zero(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        assert tx.budget_counters(["nope"]) == {"nope": 0.0}


def test_reserve_all_is_all_or_nothing(db: SQLiteStorage) -> None:
    a = BudgetCharge("cap", "k:a", 50, 100)
    b = BudgetCharge("cap2", "k:b", 5, 10)
    with db.transaction() as tx:
        tx.reserve_budget("k:b", 8, 10)
        assert not tx.reserve_all([a, b])  # b would exceed, so a is not reserved either
        assert tx.budget_counters(["k:a", "k:b"]) == {"k:a": 0.0, "k:b": 8.0}
        assert tx.reserve_all([a])
        assert tx.budget_counters(["k:a"]) == {"k:a": 50.0}


def test_reservations_are_in_the_audit_chain_and_verified(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.reserve_budget(K, 25, 100)
        tx.release_budget(K, 5)
    kinds = [e.kind for e in db.events()]
    assert kinds == ["budget_reserved", "budget_released"]
    assert db.verify().ok


def test_editing_a_counter_directly_is_caught(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.reserve_budget(K, 25, 100)
    db._conn.execute("UPDATE budget_counters SET value = 0 WHERE scope_key = ?", (K,))
    result = db.verify()
    assert not result.ok
    assert "budget" in (result.reason or "")


def test_budget_event_kinds_are_reserved(db: SQLiteStorage) -> None:
    with pytest.raises(StorageError, match="reserved"), db.transaction() as tx:
        tx.append_event("budget_reserved", {"scope_key": K, "amount": 1})


def test_concurrent_reservations_never_exceed_the_limit(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    SQLiteStorage.open(path, Redactor(KEY)).close()

    def spender(_: int) -> int:
        won = 0
        with SQLiteStorage.open(path, Redactor(KEY), busy_timeout_ms=60_000) as db:
            for _ in range(10):
                with db.transaction() as tx:
                    if tx.reserve_budget(K, 7, 100):
                        won += 1
        return won

    with ThreadPoolExecutor(max_workers=12) as pool:
        wins = sum(pool.map(spender, range(12)))
    with SQLiteStorage.open(path, Redactor(KEY)) as db, db.transaction() as tx:
        total = tx.budget_counters([K])[K]
    assert wins == 14  # floor(100 / 7)
    assert total == 98.0
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        assert db.verify().ok
