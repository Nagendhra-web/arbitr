"""SQL previews: counted on a real read-only SQLite database, never guessed."""

from __future__ import annotations

import sqlite3
import time
from typing import TYPE_CHECKING

import pytest

from arbitr.preview import DEADLINE
from arbitr.preview.sql import CONNECTION, Unsupported, count_plan, preview_sql

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "shop.db"
    conn = sqlite3.connect(path)
    with conn:
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT, total REAL)")
        conn.executemany(
            "INSERT INTO orders (status, total) VALUES (?, ?)",
            [("old" if i % 4 else "new", float(i)) for i in range(1, 2001)],
        )
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY)")
        conn.executemany("INSERT INTO items (id) VALUES (?)", [(i,) for i in range(30)])
    conn.close()
    return path


@pytest.fixture
def read_only(db: Path) -> Iterator[Callable[[], sqlite3.Connection]]:
    opened: list[sqlite3.Connection] = []

    def connect() -> sqlite3.Connection:
        conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        opened.append(conn)
        return conn

    yield connect
    for conn in opened:
        conn.close()


def _counts(db: Path) -> tuple[int, int]:
    conn = sqlite3.connect(db)
    try:
        orders = conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        items = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    finally:
        conn.close()
    return int(orders), int(items)


@pytest.mark.parametrize(
    ("sql", "rows", "summary"),
    [
        ("DELETE FROM orders WHERE status = 'old'", 1500,
         "DELETE would remove 1,500 rows from orders"),
        ("DELETE FROM orders AS o WHERE o.id <= 10", 10, "DELETE would remove 10 rows from orders"),
        ("UPDATE orders SET total = 0 WHERE id IN (SELECT id FROM items)", 29,
         "UPDATE would change 29 rows in orders"),
        ("DELETE FROM orders", 2000, "DELETE would remove 2,000 rows from orders"),
        ("UPDATE orders SET status = 'x'", 2000, "UPDATE would change 2,000 rows in orders"),
        ("DROP TABLE orders", 2000, "DROP TABLE would remove 2,000 rows from orders"),
        ("DROP TABLE IF EXISTS orders, items", 2030,
         "DROP TABLE would remove 2,030 rows from orders, items"),
        ("TRUNCATE TABLE items", 30, "TRUNCATE would remove 30 rows from items"),
        ("DELETE FROM orders WHERE id = 1", 1, "DELETE would remove 1 row from orders"),
    ],
)  # fmt: skip
def test_counts_rows_without_changing_them(
    db: Path, read_only: Callable[[], sqlite3.Connection], sql: str, rows: int, summary: str
) -> None:
    before = _counts(db)
    preview = preview_sql({"sql": sql}, {CONNECTION: read_only})
    assert preview.ok, preview
    assert preview.facts["rows_affected"] == rows
    assert preview.summary == summary
    assert _counts(db) == before


def test_uses_a_connection_object_and_leaves_it_open(db: Path) -> None:
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, check_same_thread=False)
    try:
        preview = preview_sql({"query": "DELETE FROM items WHERE id < 5"}, {CONNECTION: conn})
        assert preview.facts == {"rows_affected": 5, "tables": 1, "table": "items"}
        assert conn.execute("SELECT 1").fetchone() == (1,)  # still open
    finally:
        conn.close()


def test_finds_sql_under_other_argument_names(read_only: Callable[[], sqlite3.Connection]) -> None:
    for key in ("statement", "raw_sql", "cleanup_sql"):
        assert preview_sql({key: "DELETE FROM items"}, {CONNECTION: read_only}).ok
    assert preview_sql({"statements": ["DELETE FROM items"]}, {CONNECTION: read_only}).ok


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"sql": 5},
        {"sql": "DELETE FROM items", "query": "DELETE FROM orders"},
        {"statements": ["DELETE FROM items", "DELETE FROM orders"]},
    ],
)
def test_fails_without_exactly_one_statement(
    args: dict[str, object], read_only: Callable[[], sqlite3.Connection]
) -> None:
    assert not preview_sql(args, {CONNECTION: read_only}).ok


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM orders WHERE id = 1; DROP TABLE items",
        "DELETE FROM orders USING items WHERE orders.id = items.id",
        "UPDATE orders SET total = 0 FROM items WHERE orders.id = items.id",
        "DELETE FROM orders WHERE id > 1 LIMIT 5",
        "WITH c AS (SELECT 1) DELETE FROM orders WHERE id IN (SELECT * FROM c)",
        "DELETE FROM orders WHERE id = ?",
        "DELETE FROM orders WHERE id = :id",
        "DELETE FROM orders WHERE id > 1 RETURNING id",
        "SELECT * FROM orders",
        "INSERT INTO orders (status) VALUES ('x')",
        "DROP VIEW v",
        "DROP TABLE orders CASCADE",
        "DELETE FROM (SELECT 1) WHERE 1",
        "this is not sql (",
        "",
    ],
)
def test_refuses_what_it_cannot_rewrite_safely(
    db: Path, read_only: Callable[[], sqlite3.Connection], sql: str
) -> None:
    before = _counts(db)
    preview = preview_sql({"sql": sql}, {CONNECTION: read_only})
    assert not preview.ok
    assert preview.facts == {}
    assert _counts(db) == before


def test_count_plan_rewrites_to_a_count() -> None:
    plan = count_plan("DELETE FROM main.orders WHERE status = 'old' AND id > 3")
    assert plan.verb == "DELETE"
    assert plan.tables == ("main.orders",)
    assert plan.queries == ("SELECT COUNT(*) FROM main.orders WHERE status = 'old' AND id > 3",)
    with pytest.raises(Unsupported, match="single statement"):
        count_plan("DELETE FROM a; DELETE FROM b")


def test_needs_a_connection() -> None:
    preview = preview_sql({"sql": "DELETE FROM items"}, {})
    assert not preview.ok
    assert "connection" in preview.summary


def test_reports_query_errors(read_only: Callable[[], sqlite3.Connection]) -> None:
    preview = preview_sql({"sql": "DELETE FROM missing WHERE id = 1"}, {CONNECTION: read_only})
    assert not preview.ok
    assert preview.summary == "Preview failed: the count query did not run"
    assert preview.error is not None
    assert "OperationalError" in preview.error


def test_refuses_a_count_that_is_not_a_number() -> None:
    class Cursor:
        def execute(self, sql: str) -> None:
            pass

        def fetchone(self) -> tuple[object]:
            return ("many",)

        def close(self) -> None:
            pass

    class Conn:
        def cursor(self) -> Cursor:
            return Cursor()

    preview = preview_sql({"sql": "DELETE FROM items"}, {CONNECTION: Conn()})
    assert not preview.ok


def test_stops_a_query_after_the_deadline(read_only: Callable[[], sqlite3.Connection]) -> None:
    context = {CONNECTION: read_only, DEADLINE: time.monotonic() - 1}
    heavy = "DELETE FROM orders WHERE id IN (SELECT a.id FROM orders a, orders b, orders c)"
    preview = preview_sql({"sql": heavy}, context)
    assert not preview.ok
    assert preview.error is not None
    assert preview.error == "OperationalError"  # SQLite reports the interrupt this way


def test_database_errors_never_reach_the_record() -> None:
    """An error message can carry data (a failed CAST shows the value), so only the type is kept."""
    secret = "s3cr" + "et-value-123"
    preview = preview_sql({"sql": "DELETE FROM items WHERE id = 1"},
                          {CONNECTION: lambda: _failing(secret)})  # fmt: skip
    assert not preview.ok
    assert secret not in f"{preview.summary}{preview.error}"
    assert preview.error == "RuntimeError"


def _failing(message: str) -> object:
    class Cursor:
        def execute(self, sql: str) -> None:
            self.last = sql
            if sql.startswith("SELECT COUNT"):
                raise RuntimeError(f"invalid input syntax for integer: {message}")

        def fetchone(self) -> tuple[object]:
            return ("on",) if self.last.startswith("SHOW") else (0,)

        def close(self) -> None:
            pass

    class Conn:
        def cursor(self) -> Cursor:
            return Cursor()

        def rollback(self) -> None:
            pass

        def close(self) -> None:
            pass

    return Conn()


def test_unknown_functions_in_the_where_clause_are_refused() -> None:
    with pytest.raises(Unsupported, match="function"):
        count_plan("DELETE FROM items WHERE my_side_effect(id) = 1")


def test_sqlite_counts_run_with_query_only_and_restore_it(db: Path) -> None:
    conn = sqlite3.connect(db)
    try:
        seen: list[int] = []
        conn.set_trace_callback(lambda sql: seen.append(1) if "query_only" in sql else None)
        preview = preview_sql({"sql": "DELETE FROM items WHERE id > 0"}, {CONNECTION: conn})
        assert preview.ok
        assert seen, "PRAGMA query_only was set for the count"
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 0  # restored afterwards
    finally:
        conn.close()


def test_other_databases_count_in_a_read_only_transaction_then_roll_back() -> None:
    statements: list[str] = []
    rolled_back: list[bool] = []

    class Cursor:
        def execute(self, sql: str) -> None:
            statements.append(sql)

        def fetchone(self) -> tuple[object]:
            return ("on",) if statements[-1].startswith("SHOW") else (7,)

        def close(self) -> None:
            pass

    class Conn:
        def cursor(self) -> Cursor:
            return Cursor()

        def rollback(self) -> None:
            rolled_back.append(True)

        def close(self) -> None:
            pass

    def connect() -> Conn:  # a factory: the preview owns, rolls back and closes its connection
        return Conn()

    preview = preview_sql({"sql": "DELETE FROM items WHERE id > 3"}, {CONNECTION: connect})
    assert preview.ok
    assert statements[0] == "SET TRANSACTION READ ONLY"
    assert rolled_back == [True]


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM items WHERE id = 1 /*! OR 1 = 1 */",
        "DELETE FROM items WHERE id = 1 -- AND safe = 1",
        "DELETE FROM items WHERE id = 1 # mysql comment",
    ],
)
def test_statements_with_comments_are_refused(sql: str) -> None:
    with pytest.raises(Unsupported, match="comment"):
        count_plan(sql)


def test_a_shared_connection_to_another_database_is_refused() -> None:
    class Conn:
        def cursor(self) -> object:
            raise AssertionError("never used")

    preview = preview_sql({"sql": "DELETE FROM items WHERE id > 3"}, {CONNECTION: Conn()})
    assert not preview.ok
    assert "factory" in preview.summary


@pytest.mark.parametrize(("flag", "ok"), [("on", True), ("off", False), (None, False)])
def test_a_read_only_transaction_is_confirmed_before_counting(flag: object, ok: bool) -> None:
    class Cursor:
        def __init__(self) -> None:
            self.last = ""

        def execute(self, sql: str) -> None:
            self.last = sql
            if sql.startswith("SHOW") and flag is None:
                raise RuntimeError("unknown setting")

        def fetchone(self) -> tuple[object]:
            return (flag,) if self.last.startswith(("SHOW", "SELECT @@")) else (3,)

        def close(self) -> None:
            pass

    class Conn:
        def cursor(self) -> Cursor:
            return Cursor()

        def rollback(self) -> None:
            pass

        def close(self) -> None:
            pass

    def connect() -> Conn:
        return Conn()

    preview = preview_sql({"sql": "DELETE FROM items WHERE id > 3"}, {CONNECTION: connect})
    assert preview.ok is ok
