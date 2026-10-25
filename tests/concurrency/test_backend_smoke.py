"""Backend reachability with the settings the ledger requires.

Runs against the backend chosen by ARBITR_TEST_BACKEND (sqlite by default,
postgres in the Postgres CI stage). Replaced by the shared storage and
concurrency suites as they land.
"""

from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

pytestmark = pytest.mark.backend

BACKEND = os.environ.get("ARBITR_TEST_BACKEND", "sqlite")


def test_backend_accepts_concurrent_unique_inserts(tmp_path: Path) -> None:
    """Many threads race to insert one key. Exactly one wins."""
    if BACKEND == "sqlite":
        path = tmp_path / "ledger.db"
        with sqlite3.connect(path) as conn:
            assert conn.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
            conn.execute("CREATE TABLE k (key TEXT PRIMARY KEY)")

        def attempt(_: int) -> bool:
            conn = sqlite3.connect(path, timeout=30)
            try:
                conn.execute("PRAGMA synchronous=FULL")
                with conn:
                    conn.execute("INSERT INTO k VALUES ('same-key')")
            except sqlite3.IntegrityError:
                return False
            finally:
                conn.close()
            return True

    elif BACKEND == "postgres":
        import psycopg  # noqa: PLC0415, a missing driver must fail, never skip

        url = os.environ["ARBITR_TEST_POSTGRES_URL"]
        table = f"k_{os.getpid()}"
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
            conn.execute(f"CREATE TABLE {table} (key TEXT PRIMARY KEY)")

        def attempt(_: int) -> bool:
            try:
                with psycopg.connect(url) as conn:
                    conn.execute(f"INSERT INTO {table} VALUES ('same-key')")  # noqa: S608
            except psycopg.errors.UniqueViolation:
                return False
            return True

    else:
        pytest.fail(f"unknown ARBITR_TEST_BACKEND {BACKEND!r}")

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(50)))
    assert results.count(True) == 1
