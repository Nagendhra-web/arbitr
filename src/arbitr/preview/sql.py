"""SQL previews: how many rows a DELETE, UPDATE, DROP TABLE or TRUNCATE would touch.

The statement is parsed (with the ``sql`` extra, ``sqlglot``) and rewritten
to ``SELECT COUNT(*) FROM <table> WHERE <the same condition>``, which runs on
a read-only connection from the preview context. A statement without a
``WHERE`` counts the whole table; ``DROP TABLE`` and ``TRUNCATE`` count every
table they name.

Only plain shapes are rewritten. Joins (``USING``, ``UPDATE ... FROM``),
``LIMIT``, ``RETURNING``, common table expressions, bound parameters and more
than one statement are refused with ``ok=False``: a count that might be wrong
is worse than no count.

Context keys:

- ``sql_connection``: a DB-API connection, or a function with no arguments
  that returns one (preferred: the preview runs in a worker thread, and a
  connection made by the function is closed afterwards). It must be read-only,
  for example SQLite opened with ``file:...?mode=ro`` and ``uri=True``, or a
  database user that can only ``SELECT``.
- ``sql_dialect``: the ``sqlglot`` dialect name (``postgres``, ``mysql``,
  ``sqlite``); the generic dialect when absent.

Example:
    >>> count_plan("DELETE FROM orders WHERE status = 'old'").queries
    ("SELECT COUNT(*) FROM orders WHERE status = 'old'",)
"""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from arbitr.preview.base import DEADLINE, Preview, plural

try:
    import sqlglot
    from sqlglot import exp
except ImportError:  # pragma: no cover - sqlglot is the optional "sql" extra
    _PARSER = False
else:
    _PARSER = True

if TYPE_CHECKING:
    from collections.abc import Mapping

CONNECTION: Final = "sql_connection"
DIALECT: Final = "sql_dialect"

_SQL_KEYS: Final = frozenset({"sql", "query", "statement", "sql_query", "raw_sql"})
_LIST_KEYS: Final = frozenset({"statements"})
_TABLE_PARTS: Final = frozenset({"this", "db", "catalog", "alias"})
_PROGRESS_STEPS: Final = 1000


class Unsupported(Exception):  # noqa: N818 - a reason, not an error the caller handles
    """The statement cannot be rewritten into a count safely."""


@dataclass(frozen=True)
class CountPlan:
    """The count queries that measure one statement, one per table."""

    verb: str
    tables: tuple[str, ...]
    queries: tuple[str, ...]


def _present(node: exp.Expr) -> set[str]:
    """The argument names a parsed node actually uses."""
    return {
        name
        for name, value in node.args.items()
        if value is not None and value is not False and not (isinstance(value, list) and not value)
    }


def _table(node: object) -> exp.Table:
    if (
        not isinstance(node, exp.Table)
        or not isinstance(node.this, exp.Identifier)
        or not _present(node) <= _TABLE_PARTS
    ):
        raise Unsupported("the target is not a plain table name")
    return node


def _bare_name(table: exp.Table, dialect: str | None) -> str:
    bare = table.copy()
    bare.set("alias", None)
    return str(bare.sql(dialect=dialect))


def _count_query(table: exp.Table, where: object, dialect: str | None) -> str:
    query = exp.select(exp.Count(this=exp.Star())).from_(table.copy())
    if isinstance(where, exp.Where):
        query = query.where(where.this.copy())
    return str(query.sql(dialect=dialect))


def _filtered(verb: str, node: exp.Expr, allowed: set[str], dialect: str | None) -> CountPlan:
    extra = _present(node) - allowed
    if extra:
        raise Unsupported(f"{verb} with {', '.join(sorted(extra))} cannot be previewed")
    where = node.args.get("where")
    if isinstance(where, exp.Expr) and any(where.find_all(exp.Anonymous)):
        # A function sqlglot does not know may be user-defined and do anything.
        raise Unsupported("a WHERE clause with an unknown function cannot be previewed safely")
    table = _table(node.this)
    query = _count_query(table, where, dialect)
    return CountPlan(verb, (_bare_name(table, dialect),), (query,))


def _whole_tables(verb: str, tables: list[object], dialect: str | None) -> CountPlan:
    checked = [_table(t) for t in tables]
    if not checked:
        raise Unsupported(f"{verb} names no table")
    return CountPlan(
        verb,
        tuple(_bare_name(t, dialect) for t in checked),
        tuple(_count_query(t, None, dialect) for t in checked),
    )


def _parse_one(sql: str, dialect: str | None) -> exp.Expr:
    if not _PARSER:  # pragma: no cover - sqlglot is the optional "sql" extra
        raise Unsupported("the sql extra (sqlglot) is not installed")
    if "--" in sql or "/*" in sql or ("#" in sql and dialect in (None, "mysql")):
        # A database may read a comment differently from the parser (MySQL runs
        # /*! ... */), so the count could measure another WHERE clause.
        raise Unsupported("statements with comments cannot be previewed safely")
    try:
        trees = [t for t in sqlglot.parse(sql, read=dialect) if t is not None]
    except Exception as exc:  # any parser failure means no preview
        raise Unsupported("the statement could not be parsed") from exc
    if len(trees) != 1:
        raise Unsupported("only a single statement can be previewed")
    tree = trees[0]
    if tree.find(exp.Placeholder, exp.Parameter) is not None:
        raise Unsupported("statements with bound parameters cannot be previewed")
    return tree


def count_plan(sql: str, dialect: str | None = None) -> CountPlan:
    """Rewrite one statement into the count queries that measure it.

    Raises:
        Unsupported: the statement is not one this previewer can count safely.
    """
    tree = _parse_one(sql, dialect)
    if isinstance(tree, exp.Delete):
        return _filtered("DELETE", tree, {"this", "where"}, dialect)
    if isinstance(tree, exp.Update):
        return _filtered("UPDATE", tree, {"this", "expressions", "where"}, dialect)
    if isinstance(tree, exp.Drop):
        kind = str(tree.args.get("kind") or "").upper()
        if kind != "TABLE" or _present(tree) - {"tables", "kind", "exists"}:
            raise Unsupported("only a plain DROP TABLE can be previewed")
        return _whole_tables("DROP TABLE", list(tree.args.get("tables") or []), dialect)
    if isinstance(tree, exp.TruncateTable):
        if _present(tree) - {"expressions"}:
            raise Unsupported("only a plain TRUNCATE can be previewed")
        return _whole_tables("TRUNCATE", list(tree.expressions), dialect)
    raise Unsupported("only DELETE, UPDATE, DROP TABLE and TRUNCATE can be previewed")


_CHANGE_WORD: Final = re.compile(r"\b(delete|update|drop|truncate|merge|replace)\b", re.IGNORECASE)


def changes_rows(args: Mapping[str, object]) -> bool:
    """Whether any SQL in the arguments may change rows or the schema. Fails closed.

    Only plain reads (SELECT without INTO) and plain INSERTs count as not
    changing rows. Everything else does: DELETE, UPDATE, upserts, REPLACE,
    CALL, statements the parser does not recognize, and text that does not
    parse. Without the parser, a changing keyword is enough.
    """
    texts = [v for v in _sql_values(args) if isinstance(v, str)]
    for text in texts:
        if not _PARSER:
            if _CHANGE_WORD.search(text):
                return True
            continue
        try:
            trees = sqlglot.parse(text)
        except Exception:  # noqa: BLE001 - text that does not parse may change anything
            return True
        if not all(tree is None or _leaves_rows_alone(tree) for tree in trees):
            return True
    return False


def _leaves_rows_alone(tree: exp.Expr) -> bool:
    """A plain read, or an INSERT that only adds rows (no upsert, no REPLACE)."""
    kinds = (exp.Delete, exp.Update, exp.Drop, exp.TruncateTable, exp.Merge, exp.Command)
    if any(tree.find_all(*kinds)):
        return False
    if isinstance(tree, exp.Select | exp.Union | exp.Intersect | exp.Except):
        return tree.args.get("into") is None
    if isinstance(tree, exp.Insert):
        return not any(tree.args.get(key) for key in ("conflict", "replace", "overwrite"))
    return False


def can_count(args: Mapping[str, object]) -> bool:
    """Whether the arguments hold one statement this previewer can count."""
    try:
        count_plan(_statement(args))
    except Exception:  # noqa: BLE001 - anything unparseable is simply not previewed here
        return False
    return True


def _sql_values(args: Mapping[str, object]) -> list[object]:
    found: list[object] = []
    for key, value in args.items():
        name = str(key).lower()
        if name in _SQL_KEYS or name.endswith("_sql"):
            found.append(value)
        elif name in _LIST_KEYS and isinstance(value, list | tuple):
            found.extend(value)
    return found


def _statement(args: Mapping[str, object]) -> str:
    found = _sql_values(args)
    if not found:
        raise Unsupported("no SQL statement was found in the arguments")
    if len(found) != 1 or not isinstance(found[0], str):
        raise Unsupported("the arguments hold more than one statement, or one that is not text")
    return found[0]


def _connection(source: object) -> tuple[Any, bool]:
    """The connection to use, and whether this preview opened it (and must close it)."""
    if callable(source) and not hasattr(source, "cursor"):
        return source(), True
    return source, False


def _watch_deadline(conn: object, context: Mapping[str, object]) -> bool:
    """On SQLite, interrupt the query once the deadline passes."""
    deadline = context.get(DEADLINE)
    if not isinstance(conn, sqlite3.Connection) or not isinstance(deadline, float):
        return False
    conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), _PROGRESS_STEPS)
    return True


def _count(conn: Any, query: str) -> int:  # noqa: ANN401 - any DB-API connection
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        row = cursor.fetchone()
    finally:
        cursor.close()
    value = row[0] if row else None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise Unsupported("the count query did not return a row count")
    return value


def _run(plan: CountPlan, context: Mapping[str, object]) -> list[int]:
    conn, owned = _connection(context[CONNECTION])
    try:
        if isinstance(conn, sqlite3.Connection):
            return _count_sqlite(conn, plan, context)
        if not owned:
            # The read-only transaction ends with a rollback, which would throw
            # away work in progress on a connection someone else is using.
            raise Unsupported(
                "for this database the preview needs a connection factory, not a shared connection"
            )
        return _count_read_only(conn, plan)
    finally:
        if owned:
            conn.close()


def _count_sqlite(
    conn: sqlite3.Connection, plan: CountPlan, context: Mapping[str, object]
) -> list[int]:
    """Count with writes refused by SQLite itself (query_only), then restore the setting."""
    before = int(conn.execute("PRAGMA query_only").fetchone()[0])
    conn.execute("PRAGMA query_only = 1")
    watched = _watch_deadline(conn, context)
    try:
        return [_count(conn, q) for q in plan.queries]
    finally:
        if watched:
            conn.set_progress_handler(None, 0)
        conn.execute(f"PRAGMA query_only = {before}")


def _count_read_only(conn: Any, plan: CountPlan) -> list[int]:  # noqa: ANN401 - any DB-API
    """Count inside a read-only transaction, and always roll it back."""
    try:
        cursor = conn.cursor()
        try:
            cursor.execute("SET TRANSACTION READ ONLY")
        finally:
            cursor.close()
        if not _read_only_confirmed(conn):
            # On an autocommit connection the setting can silently do nothing.
            raise Unsupported("the database did not confirm a read-only transaction")
        return [_count(conn, q) for q in plan.queries]
    finally:
        conn.rollback()


def _read_only_confirmed(conn: Any) -> bool:  # noqa: ANN401 - any DB-API connection
    """Ask the database whether this transaction is read-only (Postgres, then MySQL)."""
    for query in ("SHOW transaction_read_only", "SELECT @@transaction_read_only"):
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            row = cursor.fetchone()
        except Exception:  # noqa: BLE001, S112 - this database does not know the question
            continue
        finally:
            cursor.close()
        value = row[0] if row else None
        return str(value).strip().lower() in {"on", "1", "true"}
    return False


def _summary(plan: CountPlan, rows: int) -> str:
    action, place = ("change", "in") if plan.verb == "UPDATE" else ("remove", "from")
    return f"{plan.verb} would {action} {plural(rows, 'row')} {place} {', '.join(plan.tables)}"


def preview_sql(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
    """Count the rows a DELETE, UPDATE, DROP TABLE or TRUNCATE would touch.

    Example:
        >>> preview_sql({"sql": "DELETE FROM t"}, {}).summary
        'Preview failed: no read-only database connection in the preview context'
    """
    dialect = context.get(DIALECT)
    try:
        plan = count_plan(_statement(args), dialect if isinstance(dialect, str) else None)
    except Unsupported as exc:
        return Preview.failed(f"No preview: {exc}")
    if context.get(CONNECTION) is None:
        return Preview.failed(
            "Preview failed: no read-only database connection in the preview context"
        )
    try:
        counts = _run(plan, context)
    except Unsupported as exc:
        return Preview.failed(f"Preview failed: {exc}")
    except Exception as exc:  # noqa: BLE001 - a database error means no preview
        # Only the type: a database error can carry the data a query touched.
        return Preview.failed("Preview failed: the count query did not run",
                              error=type(exc).__name__)  # fmt: skip
    rows = sum(counts)
    facts: dict[str, int | float | str] = {"rows_affected": rows, "tables": len(plan.tables)}
    if len(plan.tables) == 1:
        facts["table"] = plan.tables[0]
    return Preview(_summary(plan, rows), facts)
