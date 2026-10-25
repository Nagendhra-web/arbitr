"""SQLite storage: the default ledger backend.

Durability over speed: WAL journal, ``synchronous=FULL`` (every commit is on
disk before it returns), foreign keys on, a busy timeout for concurrent
writers. Every write transaction starts with ``BEGIN IMMEDIATE``, so writers
are serialized and the audit chain cannot fork.

Secrets are redacted by construction: arguments (with the tool's redact
paths, which travel on the intent), resources, run metadata, decision reasons
and every event payload pass through the ``Redactor`` here, inside storage, so
no caller can store one by accident.

Every intent state change goes through the state machine as a compare-and-set,
optionally fenced on the attempt number and lease owner, with its audit event
in the same transaction. ``verify`` checks the hash chain and then checks that
every intent row matches the events that created and moved it.

Failures are reported as ``StorageError`` (or ``StaleStateError`` for a lost
race), never as raw ``sqlite3`` errors, so callers can fail closed.

Example:
    >>> import tempfile, pathlib
    >>> from arbitr.core.redact import Redactor
    >>> path = pathlib.Path(tempfile.mkdtemp()) / "ledger.db"
    >>> with SQLiteStorage.open(path, Redactor(b"k" * 32)) as db:
    ...     db.schema_version()
    1
"""

from __future__ import annotations

import contextlib
import json
import random
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Self

from arbitr.core.audit import Event, VerifyResult, event_hash, genesis_hash, verify_chain
from arbitr.core.canonical import canonical_json
from arbitr.core.errors import StaleStateError, StorageError
from arbitr.core.intent import new_ulid
from arbitr.core.states import IntentState, can_transition, check_transition
from arbitr.storage.migrations import SQLITE, Migration

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence
    from pathlib import Path
    from types import TracebackType

    from arbitr.core.intent import ActionIntent
    from arbitr.core.redact import Redactor

BUSY_TIMEOUT_MS: Final = 5000
_NOW_SQL: Final = "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
_UPDATABLE_ORDER: Final = (
    "decision",
    "decision_rule",
    "decision_reason",
    "shadow_decision",
    "attempt",
    "lease_owner",
    "lease_expires_at",
)
_UPDATABLE: Final = frozenset(_UPDATABLE_ORDER)
_RESERVED_DETAIL: Final = frozenset({"from", "to", "intent_id", "run_id"}) | _UPDATABLE
# One fixed statement: each column is set only when its flag parameter is 1,
# and the optional fences apply only when given. No SQL is ever built from input.
_TRANSITION_SQL: Final = (
    "UPDATE intents SET state = ?, updated_at = ?,"
    " decision = CASE WHEN ? THEN ? ELSE decision END,"
    " decision_rule = CASE WHEN ? THEN ? ELSE decision_rule END,"
    " decision_reason = CASE WHEN ? THEN ? ELSE decision_reason END,"
    " shadow_decision = CASE WHEN ? THEN ? ELSE shadow_decision END,"
    " attempt = CASE WHEN ? THEN ? ELSE attempt END,"
    " lease_owner = CASE WHEN ? THEN ? ELSE lease_owner END,"
    " lease_expires_at = CASE WHEN ? THEN ? ELSE lease_expires_at END"
    " WHERE intent_id = ? AND state = ?"
    " AND (? IS NULL OR attempt = ?) AND (? IS NULL OR lease_owner = ?)"
)
_TRANSITION_KINDS: Final = frozenset(s.value.lower() for s in IntentState)
_RESERVED_KINDS: Final = _TRANSITION_KINDS | {"run_started", "intent_created"}
# What a new intent's updatable columns hold before any transition sets them.
_COLUMN_DEFAULTS: Final[dict[str, object]] = {
    "decision": None,
    "decision_rule": None,
    "decision_reason": None,
    "shadow_decision": None,
    "attempt": 0,
    "lease_owner": None,
    "lease_expires_at": None,
}
# Every intent column verify compares with the facts recorded in the events.
_CHECKED_COLUMNS: Final = (
    "intent_hash",
    "idempotency_key",
    "args_redacted",
    "tool",
    "effect",
    "step_id",
    "run_id",
    *_UPDATABLE_ORDER,
)


@dataclass(frozen=True)
class IntentRow:
    """An intent as stored. ``args_redacted`` never contains secrets."""

    intent_id: str
    run_id: str
    step_id: str | None
    tool: str
    args_redacted: str
    intent_hash: str
    idempotency_key: str
    effect: str
    resources: str
    state: IntentState
    decision: str | None
    decision_rule: str | None
    decision_reason: str | None
    shadow_decision: str | None
    attempt: int
    lease_owner: str | None
    lease_expires_at: str | None
    created_at: str
    updated_at: str


class Transaction:
    """One write transaction. Obtain it from ``SQLiteStorage.transaction()``.

    It stops working the moment its ``with`` block ends.
    """

    def __init__(self, conn: sqlite3.Connection, redactor: Redactor, genesis: str) -> None:
        """Wrap an open transaction. Use ``SQLiteStorage.transaction()`` instead."""
        self._conn = conn
        self._redactor = redactor
        self._genesis = genesis
        self._closed = False
        self.now: str = conn.execute(_NOW_SQL).fetchone()[0]
        """The database clock at the start of this transaction (UTC, ISO 8601)."""

    def _live(self) -> sqlite3.Connection:
        if self._closed:
            raise StorageError("this transaction is closed; start a new one")
        return self._conn

    # ------------------------------------------------------------ events

    def append_event(
        self,
        kind: str,
        payload: Mapping[str, object],
        *,
        intent_id: str | None = None,
        run_id: str | None = None,
    ) -> Event:
        """Append one event to the audit chain. The payload is redacted first.

        Lifecycle kinds (``run_started``, ``intent_created`` and one per intent
        state) are written only by storage itself, so they cannot be forged.

        Raises:
            StorageError: ``kind`` is a reserved lifecycle kind.
        """
        if kind in _RESERVED_KINDS:
            raise StorageError(f"event kind {kind!r} is reserved for storage itself")
        return self._append(kind, payload, intent_id=intent_id, run_id=run_id)

    def _append(
        self,
        kind: str,
        payload: Mapping[str, object],
        *,
        intent_id: str | None = None,
        run_id: str | None = None,
    ) -> Event:
        conn = self._live()
        body = canonical_json(self._redactor.redact(dict(payload)))
        row = conn.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else self._genesis
        digest = event_hash(prev, kind, body, self.now, intent_id=intent_id, run_id=run_id)
        cur = conn.execute(
            "INSERT INTO events (intent_id, run_id, kind, payload, prev_hash, hash, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (intent_id, run_id, kind, body, prev, digest, self.now),
        )
        seq = cur.lastrowid
        if seq is None:  # pragma: no cover, sqlite always sets it for an INSERT
            raise StorageError("event insert returned no row id")
        return Event(seq, intent_id, run_id, kind, body, prev, digest, self.now)

    # ------------------------------------------------------------ runs

    def insert_run(  # noqa: PLR0913, a run has this many independent attributes
        self,
        run_id: str,
        principal: str,
        agent_id: str,
        *,
        mode: str = "enforce",
        parent_run_id: str | None = None,
        scopes: Sequence[str] = (),
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Record a new run and its ``run_started`` event."""
        conn = self._live()
        meta = canonical_json(self._redactor.redact(dict(metadata or {})))
        conn.execute(
            "INSERT INTO runs (run_id, principal, agent_id, parent_run_id, scopes, mode,"
            " created_at, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                principal,
                agent_id,
                parent_run_id,
                canonical_json(list(scopes)),
                mode,
                self.now,
                meta,
            ),
        )
        self._append(
            "run_started",
            {
                "principal": principal,
                "agent_id": agent_id,
                "mode": mode,
                "parent_run_id": parent_run_id,
            },
            run_id=run_id,
        )

    # ------------------------------------------------------------ intents

    def insert_intent(self, intent: ActionIntent, redact_paths: Sequence[str] = ()) -> IntentRow:
        """Record a new intent in PROPOSED with its ``intent_created`` event.

        The tool's redact paths travel on the intent and are always applied;
        ``redact_paths`` adds more.

        Raises:
            StaleStateError: an intent with the same idempotency key already exists.
        """
        conn = self._live()
        paths = (*intent.redact_paths, *redact_paths)
        args = self._redactor.redact(intent.args, paths)
        args_json = canonical_json(args)
        resources = canonical_json(
            [
                {
                    "kind": r.kind,
                    "uri": self._redactor.redact_text(r.uri),
                    "attrs": self._redactor.redact(dict(r.attrs)),
                }
                for r in intent.resources
            ]
        )
        try:
            conn.execute(
                "INSERT INTO intents (intent_id, run_id, step_id, tool, args_redacted,"
                " intent_hash, idempotency_key, effect, resources, state, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    intent.intent_id,
                    intent.run_id,
                    intent.step_id,
                    intent.tool,
                    args_json,
                    intent.intent_hash,
                    intent.idempotency_key,
                    intent.effect,
                    resources,
                    IntentState.PROPOSED.value,
                    self.now,
                    self.now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if "idempotency_key" in str(exc):
                raise StaleStateError(
                    f"an intent with idempotency key {intent.idempotency_key} already exists"
                ) from exc
            raise StorageError(f"could not record intent: {exc}") from exc
        self._append(
            "intent_created",
            {
                "tool": intent.tool,
                "args": args,
                "effect": intent.effect,
                "intent_hash": intent.intent_hash,
                "idempotency_key": intent.idempotency_key,
                "step_id": intent.step_id,
            },
            intent_id=intent.intent_id,
            run_id=intent.run_id,
        )
        row = self.get_intent(intent.intent_id)
        if row is None:  # pragma: no cover, just inserted in this transaction
            raise StorageError("intent vanished inside its own transaction")
        return row

    def get_intent(self, intent_id: str) -> IntentRow | None:
        """Return the intent with this id, or None."""
        return _fetch_intent(self._live(), "intent_id", intent_id)

    def get_intent_by_key(self, idempotency_key: str) -> IntentRow | None:
        """Return the intent with this idempotency key, or None."""
        return _fetch_intent(self._live(), "idempotency_key", idempotency_key)

    def transition(  # noqa: PLR0913, the fences and extras are all optional keywords
        self,
        intent_id: str,
        target: IntentState,
        *,
        expected: IntentState,
        fields: Mapping[str, object] | None = None,
        detail: Mapping[str, object] | None = None,
        expected_attempt: int | None = None,
        expected_lease_owner: str | None = None,
    ) -> IntentRow:
        """Move an intent from ``expected`` to ``target``, with its event.

        This is a compare-and-set. If another writer moved the intent first, or
        the optional fences do not match (a stale attempt or a lost lease),
        nothing changes and ``StaleStateError`` is raised.

        Raises:
            IllegalTransitionError: ``expected -> target`` is not in the state machine.
            StaleStateError: the intent is missing, moved, or fenced off.
            StorageError: ``fields`` names a column that may not be updated, or
                ``detail`` tries to overwrite a recorded fact.
        """
        conn = self._live()
        check_transition(expected, target)
        updates = dict(fields or {})
        bad = set(updates) - _UPDATABLE
        if bad:
            raise StorageError(f"these intent fields cannot be updated: {sorted(bad)}")
        extra = dict(detail or {})
        clash = set(extra) & (_RESERVED_DETAIL | set(updates))
        if clash:
            raise StorageError(f"detail keys may not overwrite recorded facts: {sorted(clash)}")
        if isinstance(updates.get("decision_reason"), str):
            updates["decision_reason"] = self._redactor.redact_text(str(updates["decision_reason"]))

        params: list[object] = [target.value, self.now]
        for name in _UPDATABLE_ORDER:
            params += [name in updates, updates.get(name)]
        params += [intent_id, expected.value]
        params += [expected_attempt, expected_attempt, expected_lease_owner, expected_lease_owner]
        cur = conn.execute(_TRANSITION_SQL, params)
        if cur.rowcount != 1:
            raise StaleStateError(
                f"intent {intent_id} is not in state {expected} with the expected attempt and"
                " lease any more (or does not exist)"
            )
        row = self.get_intent(intent_id)
        if row is None:  # pragma: no cover, the update above matched it
            raise StorageError("intent vanished inside its own transaction")
        self._append(
            target.value.lower(),
            {"from": expected.value, "to": target.value, **updates, **extra},
            intent_id=intent_id,
            run_id=row.run_id,
        )
        return row


def _fetch_intent(conn: sqlite3.Connection, column: str, value: str) -> IntentRow | None:
    sql = {
        "intent_id": "SELECT * FROM intents WHERE intent_id = ?",
        "idempotency_key": "SELECT * FROM intents WHERE idempotency_key = ?",
    }[column]
    cur = conn.execute(sql, (value,))
    row = cur.fetchone()
    if row is None:
        return None
    data = dict(zip([d[0] for d in cur.description], row, strict=True))
    data["state"] = IntentState(data["state"])
    return IntentRow(**data)


def _is_busy(exc: sqlite3.Error) -> bool:
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def _enable_wal(conn: sqlite3.Connection, busy_timeout_ms: int) -> None:
    """Switch to WAL, retrying while another opener holds the lock.

    ``PRAGMA journal_mode`` does not use SQLite's busy handler, so concurrent
    first opens need an explicit, bounded retry with jittered backoff.
    """
    deadline = time.monotonic() + busy_timeout_ms / 1000
    delay = 0.005
    while True:
        try:
            mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        except sqlite3.OperationalError as exc:
            if not _is_busy(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(delay * (0.5 + random.random()))  # noqa: S311, jitter only
            delay = min(delay * 2, 0.25)
            continue
        if str(mode).lower() != "wal":
            raise StorageError(f"could not enable WAL mode (got {mode})")
        return


class SQLiteStorage:
    """A ledger stored in one SQLite file."""

    def __init__(self, conn: sqlite3.Connection, redactor: Redactor) -> None:
        """Wrap a connection. Use ``SQLiteStorage.open()`` instead."""
        self._conn = conn
        self._redactor = redactor
        self._genesis = ""

    @classmethod
    def open(
        cls, path: str | Path, redactor: Redactor, *, busy_timeout_ms: int = BUSY_TIMEOUT_MS
    ) -> SQLiteStorage:
        """Open (or create) a ledger file, apply pending migrations and return it.

        Safe to call from many threads and processes at once on a new file.

        Raises:
            StorageError: the file cannot be opened or migrated, or its schema is
                newer than this version of Arbitr knows.
        """
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(str(path), isolation_level=None, timeout=busy_timeout_ms / 1000)
            conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
            _enable_wal(conn, busy_timeout_ms)
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("PRAGMA foreign_keys = ON")
            storage = cls(conn, redactor)
            storage.migrate()
            storage._genesis = genesis_hash(storage.install_id())
        except sqlite3.Error as exc:
            if conn is not None:
                conn.close()
            raise StorageError(f"cannot open ledger at {path}: {exc}") from exc
        except BaseException:
            if conn is not None:
                conn.close()
            raise
        return storage

    def __enter__(self) -> Self:
        """Use the storage as a context manager that closes it on exit."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the connection."""
        self.close()

    def close(self) -> None:
        """Close the connection."""
        self._conn.close()

    # ------------------------------------------------------------ schema

    def migrate(self, migrations: Sequence[Migration] = SQLITE) -> list[int]:
        """Apply every migration newer than the current schema. Returns those applied.

        Each migration runs in its own ``BEGIN IMMEDIATE`` transaction and
        re-reads the schema version inside it, so concurrent openers never apply
        one twice.

        Raises:
            StorageError: a migration fails (it is rolled back), or the database
                is newer than the newest migration given.
        """
        known = max((m.version for m in migrations), default=0)
        try:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_version ("
                " version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
        except sqlite3.Error as exc:
            raise StorageError(f"cannot prepare the schema table: {exc}") from exc
        current = self.schema_version()
        if current > known:
            raise StorageError(
                f"ledger schema version {current} is newer than this Arbitr knows ({known});"
                " upgrade Arbitr before opening it"
            )
        applied: list[int] = []
        for migration in sorted(migrations, key=lambda m: m.version):
            if migration.version <= current:
                continue
            with self._raw_transaction() as conn:
                if self._version(conn) >= migration.version:
                    continue  # another opener applied it while we waited for the lock
                try:
                    # Statements one by one, inside our transaction (executescript commits).
                    for statement in _split_sql(migration.sql):
                        conn.execute(statement)
                    conn.execute(
                        "INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)",
                        (migration.version, migration.name, conn.execute(_NOW_SQL).fetchone()[0]),
                    )
                    if migration.version == 1:
                        conn.execute(
                            "INSERT OR IGNORE INTO meta (key, value) VALUES ('install_id', ?)",
                            (new_ulid(),),
                        )
                except sqlite3.Error as exc:
                    raise StorageError(
                        f"migration {migration.version} ({migration.name}) failed: {exc}"
                    ) from exc
            applied.append(migration.version)
            current = migration.version
        return applied

    @staticmethod
    def _version(conn: sqlite3.Connection) -> int:
        row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return int(row[0] or 0)

    def schema_version(self) -> int:
        """Return the newest applied migration version, 0 for an empty database."""
        try:
            return self._version(self._conn)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot read the schema version: {exc}") from exc

    def install_id(self) -> str:
        """Return this ledger's install id, created with the schema."""
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'install_id'").fetchone()
        if row is None:
            raise StorageError("ledger has no install id; the schema is incomplete")
        return str(row[0])

    # ------------------------------------------------------------ transactions

    def _rollback_quietly(self) -> None:
        # Roll back only a transaction that is still open, and never let a
        # rollback error hide the error that caused it.
        if self._conn.in_transaction:
            with contextlib.suppress(sqlite3.Error):
                self._conn.execute("ROLLBACK")

    @contextmanager
    def _raw_transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise StorageError(f"cannot start a ledger transaction: {exc}") from exc
        try:
            yield self._conn
        except sqlite3.Error as exc:
            self._rollback_quietly()
            raise StorageError(f"ledger write failed: {exc}") from exc
        except BaseException:
            self._rollback_quietly()
            raise
        try:
            self._conn.execute("COMMIT")
        except sqlite3.Error as exc:
            self._rollback_quietly()
            raise StorageError(f"ledger commit failed: {exc}") from exc

    @contextmanager
    def transaction(self) -> Iterator[Transaction]:
        """A write transaction. Commits on success, rolls back on any error.

        Raises:
            StorageError: the transaction cannot start, a statement fails, or the
                commit fails. The ledger is unchanged in every case (fail closed).
        """
        with self._raw_transaction() as conn:
            tx = Transaction(conn, self._redactor, self._genesis)
            try:
                yield tx
            finally:
                tx._closed = True  # the owner retires its transaction

    # ------------------------------------------------------------ audit

    def events(self, after_seq: int = 0) -> Iterator[Event]:
        """Yield audit events in sequence order."""
        cur = self._conn.execute(
            "SELECT seq, intent_id, run_id, kind, payload, prev_hash, hash, created_at"
            " FROM events WHERE seq > ? ORDER BY seq",
            (after_seq,),
        )
        for row in cur:
            yield Event(*row)

    def verify(self) -> VerifyResult:
        """Check the hash chain, then check every intent against its events.

        An intent row must match its ``intent_created`` event (hash, key and
        stored arguments) and its state must be the target of its latest
        transition event. Events must not refer to intents that no longer exist.
        """
        chain = verify_chain(self.events(), self._genesis)
        if not chain.ok:
            return chain
        problem = self._check_intents()
        if problem:
            return VerifyResult(ok=False, checked=chain.checked, reason=problem)
        return chain

    def _check_intents(self) -> str | None:
        expected, problem = self._replay_intent_events()
        if problem:
            return problem
        return self._compare_intents(expected)

    def _replay_intent_events(self) -> tuple[dict[str, dict[str, object]], str | None]:
        """Rebuild each intent's expected identity and state from its events."""
        expected: dict[str, dict[str, object]] = {}
        for event in self.events():
            if event.intent_id is None:
                continue
            payload = json.loads(event.payload)
            if event.kind == "intent_created":
                expected[event.intent_id] = {
                    "intent_hash": payload.get("intent_hash"),
                    "idempotency_key": payload.get("idempotency_key"),
                    "args_redacted": canonical_json(payload.get("args")),
                    "tool": payload.get("tool"),
                    "effect": payload.get("effect"),
                    "step_id": payload.get("step_id"),
                    "run_id": event.run_id,
                    "state": IntentState.PROPOSED.value,
                    **_COLUMN_DEFAULTS,
                }
            elif event.kind in _TRANSITION_KINDS and "to" in payload:
                facts = expected.get(event.intent_id)
                if facts is None:
                    return expected, f"event {event.seq} moves {event.intent_id} before it exists"
                if payload.get("from") != facts["state"] or not can_transition(
                    IntentState(payload["from"]), IntentState(payload["to"])
                ):
                    return expected, f"event {event.seq} records an impossible move"
                facts["state"] = payload["to"]
                for name in _UPDATABLE_ORDER:
                    if name in payload:
                        facts[name] = payload[name]
        return expected, None

    def _compare_intents(self, expected: dict[str, dict[str, object]]) -> str | None:
        """Check every intent row against the facts its events recorded."""
        rows = {r.intent_id: r for r in self._all_intents()}
        for intent_id in expected.keys() - rows.keys():
            return f"intent {intent_id} has events but its record is missing"
        for intent_id, row in rows.items():
            facts = expected.get(intent_id)
            if facts is None:
                return f"intent {intent_id} has no intent_created event"
            for name in _CHECKED_COLUMNS:
                if getattr(row, name) != facts[name]:
                    return f"intent {intent_id} {name} does not match its recorded events"
            if row.state.value != facts["state"]:
                return f"intent {intent_id} is {row.state} but its events end in {facts['state']}"
        return None

    def _all_intents(self) -> Iterator[IntentRow]:
        cur = self._conn.execute("SELECT * FROM intents")
        names = [d[0] for d in cur.description]
        for row in cur:
            data = dict(zip(names, row, strict=True))
            data["state"] = IntentState(data["state"])
            yield IntentRow(**data)

    def intent_count(self) -> int:
        """Number of stored intents."""
        return int(self._conn.execute("SELECT COUNT(*) FROM intents").fetchone()[0])


def _split_sql(script: str) -> list[str]:
    """Split a migration into statements. Migrations contain no semicolons in strings."""
    return [s.strip() for s in script.split(";") if s.strip()]


def decode_args(row: IntentRow) -> object:
    """Parse the stored (redacted) arguments of an intent."""
    return json.loads(row.args_redacted)
