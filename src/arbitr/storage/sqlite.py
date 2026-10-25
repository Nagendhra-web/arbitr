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
    4
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import random
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, Self

from arbitr.core.audit import Event, VerifyResult, event_hash, genesis_hash, verify_chain
from arbitr.core.canonical import canonical_json
from arbitr.core.errors import CanonicalizationError, ScopeError, StaleStateError, StorageError
from arbitr.core.intent import new_ulid
from arbitr.core.scope import Scope
from arbitr.core.states import IntentState, can_transition, check_transition
from arbitr.core.taint import Taint, merge
from arbitr.storage.migrations import SQLITE, Migration

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence
    from pathlib import Path
    from types import TracebackType

    from arbitr.core.intent import ActionIntent
    from arbitr.core.redact import Redactor
    from arbitr.policy.engine import BudgetCharge

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
    "scheduled_for",
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
    " lease_expires_at = CASE WHEN ? THEN ? ELSE lease_expires_at END,"
    " scheduled_for = CASE WHEN ? THEN ? ELSE scheduled_for END"
    " WHERE intent_id = ? AND state = ?"
    " AND (? IS NULL OR attempt = ?) AND (? IS NULL OR lease_owner = ?)"
)
_TRANSITION_KINDS: Final = frozenset(s.value.lower() for s in IntentState)
_RESERVED_KINDS: Final = _TRANSITION_KINDS | {
    "run_started",
    "intent_created",
    "budget_reserved",
    "budget_released",
    "taint_added",
    "lease_extended",
    "receipt_recorded",
    "approval_requested",
}
# What a new intent's updatable columns hold before any transition sets them.
_COLUMN_DEFAULTS: Final[dict[str, object]] = {
    "decision": None,
    "decision_rule": None,
    "decision_reason": None,
    "shadow_decision": None,
    "attempt": 0,
    "lease_owner": None,
    "lease_expires_at": None,
    "scheduled_for": None,
    "args_exact": False,
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
    "args_exact",
    *_UPDATABLE_ORDER,
)
_RESULT_LIMIT: Final = 65_536
"""Stored (redacted) results longer than this are dropped; the hash is kept."""


def parse_db_time(text: str) -> datetime:
    """Parse a database timestamp such as ``2026-10-25T12:00:00.250Z`` (UTC).

    Raises:
        StorageError: the text is not a database timestamp.
    """
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise StorageError(f"not a database timestamp: {text!r}") from exc


def format_db_time(moment: datetime) -> str:
    """Format a time the way the database clock does, in UTC with milliseconds."""
    utc = moment.astimezone(UTC)
    return f"{utc:%Y-%m-%dT%H:%M:%S}.{utc.microsecond // 1000:03d}Z"


@dataclass(frozen=True)
class RunRow:
    """A run as stored. The task text in ``scope`` is redacted."""

    run_id: str
    principal: str
    agent_id: str
    parent_run_id: str | None
    scopes: tuple[str, ...]
    scope: Scope | None
    taint: Taint
    mode: str
    created_at: str


def _run_row(row: tuple[object, ...]) -> RunRow:
    run_id, principal, agent_id, parent, scopes, scope, taint, mode, created = row
    return RunRow(
        run_id=str(run_id),
        principal=str(principal),
        agent_id=str(agent_id),
        parent_run_id=None if parent is None else str(parent),
        scopes=tuple(json.loads(str(scopes))),
        scope=Scope.model_validate(json.loads(str(scope))) if scope else None,
        taint=Taint.from_dict(json.loads(str(taint))),
        mode=str(mode),
        created_at=str(created),
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
    args_exact: bool = False
    """True when ``args_redacted`` holds the real arguments (redaction changed nothing)."""
    scheduled_for: str | None = None


@dataclass(frozen=True)
class ReceiptRow:
    """Proof that an intent's side effect happened, as stored."""

    intent_id: str
    result_hash: str
    result_redacted: str | None
    external_id: str | None
    source: str
    created_at: str


@dataclass(frozen=True)
class ApprovalRow:
    """A request for a human decision, bound to one intent hash."""

    approval_id: str
    intent_id: str
    intent_hash: str
    status: str
    requested_at: str
    expires_at: str
    decided_by: str | None
    decided_at: str | None
    note: str | None


class Transaction:
    """One write transaction. Obtain it from ``SQLiteStorage.transaction()``.

    It stops working the moment its ``with`` block ends.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        redactor: Redactor,
        genesis: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Wrap an open transaction. Use ``SQLiteStorage.transaction()`` instead."""
        self._conn = conn
        self._redactor = redactor
        self._genesis = genesis
        self._closed = False
        self.now: str = (
            conn.execute(_NOW_SQL).fetchone()[0] if clock is None else format_db_time(clock())
        )
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
        verbatim: bool = False,
    ) -> Event:
        """Chain one event. ``verbatim`` keeps the payload exactly as given.

        Storage's own events mirror fields that its tables already hold, either
        as given (ids, hashes, keys, worker names) or redacted once already
        (arguments, task text). Redacting them again could rewrite a hash or a
        marker that happens to contain a card-like digit run, and verify would
        then report a healthy ledger as tampered. Free text from callers is
        always redacted.
        """
        conn = self._live()
        body = canonical_json(dict(payload) if verbatim else self._redactor.redact(dict(payload)))
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

    # ------------------------------------------------------------ budgets

    def budget_counters(self, keys: Sequence[str]) -> dict[str, float]:
        """Current value of each budget counter; unknown keys read as 0."""
        conn = self._live()
        out = dict.fromkeys(keys, 0.0)
        for key in keys:
            row = conn.execute(
                "SELECT value FROM budget_counters WHERE scope_key = ?", (key,)
            ).fetchone()
            if row is not None:
                out[key] = float(row[0])
        return out

    def reserve_budget(
        self, key: str, amount: float, limit: float, *, intent_id: str | None = None
    ) -> bool:
        """Add ``amount`` to a counter only if it stays within ``limit``.

        Atomic: the check and the add are one statement inside this write
        transaction, so concurrent reservations can never overspend. Returns
        False, changing nothing, when the reservation would exceed the limit.
        With ``intent_id``, the reservation is also recorded against that
        intent, so ``release_reservations`` can give back exactly what it took.
        """
        conn = self._live()
        _check_amount(amount)
        _check_amount(limit)
        conn.execute(
            "INSERT OR IGNORE INTO budget_counters (scope_key, value, updated_at) VALUES (?, 0, ?)",
            (key, self.now),
        )
        cur = conn.execute(
            "UPDATE budget_counters SET value = value + ?, updated_at = ?"
            " WHERE scope_key = ? AND value + ? <= ?",
            (amount, self.now, key, amount, limit),
        )
        if cur.rowcount != 1:
            return False
        if intent_id is not None:
            conn.execute(
                "INSERT INTO reservations (intent_id, scope_key, amount) VALUES (?, ?, ?)"
                " ON CONFLICT (intent_id, scope_key)"
                " DO UPDATE SET amount = amount + excluded.amount",
                (intent_id, key, amount),
            )
        self._append(
            "budget_reserved",
            {"scope_key": key, "amount": amount, "limit": limit},
            intent_id=intent_id,
            verbatim=True,
        )
        return True

    def release_budget(self, key: str, amount: float, *, intent_id: str | None = None) -> None:
        """Return ``amount`` to a counter, for an action that did not run.

        Raises:
            StorageError: more than is reserved would be released.
        """
        conn = self._live()
        _check_amount(amount)
        cur = conn.execute(
            "UPDATE budget_counters SET value = value - ?, updated_at = ?"
            " WHERE scope_key = ? AND value >= ?",
            (amount, self.now, key, amount),
        )
        if cur.rowcount != 1:
            raise StorageError(f"cannot release more than is reserved on budget {key}")
        self._append(
            "budget_released",
            {"scope_key": key, "amount": amount},
            intent_id=intent_id,
            verbatim=True,
        )

    def reserve_all(self, charges: Sequence[BudgetCharge], *, intent_id: str | None = None) -> bool:
        """Reserve every charge, or none of them. Returns whether they were reserved.

        With ``intent_id``, the reservations are recorded against that intent.
        """
        self._live()
        totals: dict[str, float] = {}
        limits: dict[str, float] = {}
        for charge in charges:
            _check_amount(charge.amount)
            totals[charge.scope_key] = totals.get(charge.scope_key, 0.0) + charge.amount
            limits[charge.scope_key] = min(limits.get(charge.scope_key, charge.limit), charge.limit)
        current = self.budget_counters(list(totals))
        if any(current[k] + totals[k] > limits[k] for k in totals):
            return False
        for charge in charges:
            if not self.reserve_budget(
                charge.scope_key, charge.amount, charge.limit, intent_id=intent_id
            ):
                raise StorageError(  # pragma: no cover, checked above inside this transaction
                    f"budget {charge.scope_key} changed inside its own transaction"
                )
        return True

    def reservations(self, intent_id: str) -> dict[str, float]:
        """What an intent holds reserved, by budget counter."""
        rows = self._live().execute(
            "SELECT scope_key, amount FROM reservations WHERE intent_id = ? ORDER BY scope_key",
            (intent_id,),
        )
        return {str(key): float(amount) for key, amount in rows}

    def release_reservations(self, intent_id: str) -> int:
        """Give back everything an intent reserved. Returns how many counters changed.

        Safe to call twice: the second call finds nothing left to release.
        """
        held = self.reservations(intent_id)
        for key, amount in held.items():
            self.release_budget(key, amount, intent_id=intent_id)
        self._live().execute("DELETE FROM reservations WHERE intent_id = ?", (intent_id,))
        return len(held)

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
        scope: Scope | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Record a new run and its ``run_started`` event.

        A child run starts with its parent's taint, inherits its parent's scope
        when it declares none, and may not be wider than its parent in either
        its named scopes or its scope manifest. The task text is redacted.

        A child of an enforcing run cannot run in shadow mode: that would loosen
        its parent the same way a wider scope would.

        Raises:
            ScopeError: the child would be wider than its parent.
            StorageError: the parent run does not exist, or the mode is unknown.
        """
        conn = self._live()
        if mode not in ("enforce", "shadow"):
            raise StorageError(f"run mode must be enforce or shadow, not {mode!r}")
        taint = Taint()
        if parent_run_id is not None:
            parent = self.get_run(parent_run_id)
            if parent is None:
                raise StorageError(f"parent run {parent_run_id} does not exist")
            if parent.mode == "enforce" and mode == "shadow":
                raise ScopeError("a child of an enforcing run cannot run in shadow mode")
            if not set(scopes) <= set(parent.scopes):
                raise ScopeError(
                    f"child run scopes {sorted(set(scopes) - set(parent.scopes))} are not"
                    " held by its parent"
                )
            if scope is None:
                scope = parent.scope
            elif parent.scope is not None and not scope.is_within(parent.scope):
                raise ScopeError("child run scope is wider than its parent's scope")
            taint = parent.taint
        if scope is not None and scope.task is not None:
            scope = scope.model_copy(update={"task": self._redactor.redact_text(scope.task)})
        scope_json = canonical_json(scope.model_dump(mode="json")) if scope else None
        meta = canonical_json(self._redactor.redact(dict(metadata or {})))
        conn.execute(
            "INSERT INTO runs (run_id, principal, agent_id, parent_run_id, scopes, taint, mode,"
            " created_at, metadata, scope) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                principal,
                agent_id,
                parent_run_id,
                canonical_json(sorted(set(scopes))),
                canonical_json(taint.to_dict()),
                mode,
                self.now,
                meta,
                scope_json,
            ),
        )
        self._append(
            "run_started",
            {
                "principal": principal,
                "agent_id": agent_id,
                "mode": mode,
                "parent_run_id": parent_run_id,
                "scopes": sorted(set(scopes)),
                "scope": scope.model_dump(mode="json") if scope else None,
                "taint": taint.to_dict(),
            },
            run_id=run_id,
            verbatim=True,  # the task text in the scope was redacted above
        )

    def get_run(self, run_id: str) -> RunRow | None:
        """Return a run, or None."""
        row = (
            self._live()
            .execute(
                "SELECT run_id, principal, agent_id, parent_run_id, scopes, scope, taint, mode,"
                " created_at FROM runs WHERE run_id = ?",
                (run_id,),
            )
            .fetchone()
        )
        return _run_row(row) if row else None

    def add_taint(self, run_id: str, taint: Taint) -> None:
        """Taint a run, every run below it and every run above it. Taint never decreases.

        Upward because a sub-agent's output flows back into its parent's
        context: otherwise untrusted input read by a child and private data read
        by the parent would never meet. Siblings are not touched; they get the
        parent's taint only when they start after it.

        Each run whose taint changes gets a ``taint_added`` event.
        """
        conn = self._live()
        tree = conn.execute(
            "WITH RECURSIVE"
            " down(id) AS (SELECT ? UNION SELECT r.run_id FROM runs r"
            " JOIN down d ON r.parent_run_id = d.id),"
            " up(id) AS (SELECT ? UNION SELECT r.parent_run_id FROM runs r"
            " JOIN up u ON r.run_id = u.id WHERE r.parent_run_id IS NOT NULL)"
            " SELECT id FROM down UNION SELECT id FROM up ORDER BY id",
            (run_id, run_id),
        ).fetchall()
        for (rid,) in tree:
            current = self.get_run(rid)
            if current is None:
                raise StorageError(f"run {rid} does not exist")
            merged = merge(current.taint, taint)
            if merged == current.taint:
                continue
            conn.execute(
                "UPDATE runs SET taint = ? WHERE run_id = ?",
                (canonical_json(merged.to_dict()), rid),
            )
            self._append("taint_added", {"taint": merged.to_dict()}, run_id=rid)

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
        args_exact = args_json == canonical_json(intent.args)
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
                " intent_hash, idempotency_key, effect, resources, state, created_at, updated_at,"
                " args_exact) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    int(args_exact),
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
                "args_exact": args_exact,
            },
            intent_id=intent.intent_id,
            run_id=intent.run_id,
            verbatim=True,  # the arguments were redacted above
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
        payload: dict[str, object] = {"from": expected.value, "to": target.value, **updates}
        safe_detail = self._redactor.redact(extra)  # only the free-text detail is redacted
        if isinstance(safe_detail, dict):
            payload.update(safe_detail)
        self._append(
            target.value.lower(), payload, intent_id=intent_id, run_id=row.run_id, verbatim=True
        )
        return row

    # ------------------------------------------------------------ execution

    def _later(self, seconds: float) -> str:
        return format_db_time(parse_db_time(self.now) + timedelta(seconds=seconds))

    def start_execution(
        self,
        intent_id: str,
        *,
        expected: IntentState,
        worker: str,
        ttl_seconds: float,
        expected_attempt: int | None = None,
    ) -> IntentRow:
        """Move an intent to EXECUTING with the next attempt and a lease on the database clock.

        ``expected_attempt`` fences a decision made outside this transaction
        (for example a probe's answer): if another attempt started since, the
        decision is stale and nothing changes.

        Raises:
            StaleStateError: another worker moved the intent first.
        """
        row = self.get_intent(intent_id)
        if row is None:
            raise StaleStateError(f"intent {intent_id} does not exist")
        if expected_attempt is not None and row.attempt != expected_attempt:
            raise StaleStateError(
                f"intent {intent_id} is at attempt {row.attempt}, not {expected_attempt}"
            )
        return self.transition(
            intent_id,
            IntentState.EXECUTING,
            expected=expected,
            fields={
                "attempt": row.attempt + 1,
                "lease_owner": worker,
                "lease_expires_at": self._later(ttl_seconds),
            },
            expected_attempt=row.attempt,
        )

    def heartbeat(
        self, intent_id: str, *, worker: str, attempt: int, ttl_seconds: float
    ) -> IntentRow:
        """Extend a running intent's lease. Only the lease owner of that attempt can.

        Raises:
            StaleStateError: the lease was lost (expired and taken, or the intent finished).
        """
        expires = self._later(ttl_seconds)
        cur = self._live().execute(
            "UPDATE intents SET lease_expires_at = ?, updated_at = ? WHERE intent_id = ?"
            " AND state = 'EXECUTING' AND lease_owner = ? AND attempt = ?",
            (expires, self.now, intent_id, worker, attempt),
        )
        if cur.rowcount != 1:
            raise StaleStateError(f"worker {worker} no longer holds the lease on {intent_id}")
        row = self.get_intent(intent_id)
        if row is None:  # pragma: no cover, the update above matched it
            raise StorageError("intent vanished inside its own transaction")
        self._append(
            "lease_extended",
            {"lease_expires_at": expires, "lease_owner": worker, "attempt": attempt},
            intent_id=intent_id,
            run_id=row.run_id,
            verbatim=True,
        )
        return row

    def stale_executions(self) -> list[IntentRow]:
        """Intents in EXECUTING whose lease has run out, oldest id first."""
        cur = self._live().execute(
            "SELECT * FROM intents WHERE state = 'EXECUTING' AND lease_expires_at <= ?"
            " ORDER BY intent_id",
            (self.now,),
        )
        names = [d[0] for d in cur.description]
        return [_intent_row(dict(zip(names, r, strict=True))) for r in cur.fetchall()]

    def has_been(self, intent_id: str, state: IntentState) -> bool:
        """Whether the intent was ever moved to ``state`` (from its recorded events)."""
        row = (
            self._live()
            .execute(
                "SELECT 1 FROM events WHERE intent_id = ? AND kind = ? LIMIT 1",
                (intent_id, state.value.lower()),
            )
            .fetchone()
        )
        return row is not None

    def intents_in(self, state: IntentState) -> list[IntentRow]:
        """Every intent in one state, oldest id first."""
        cur = self._live().execute(
            "SELECT * FROM intents WHERE state = ? ORDER BY intent_id", (state.value,)
        )
        names = [d[0] for d in cur.description]
        return [_intent_row(dict(zip(names, r, strict=True))) for r in cur.fetchall()]

    def schedule(self, intent_id: str, *, delay_seconds: float) -> IntentRow:
        """Move an approved intent to SCHEDULED, due after the delay (a cancel window)."""
        return self.transition(
            intent_id,
            IntentState.SCHEDULED,
            expected=IntentState.APPROVED,
            fields={"scheduled_for": self._later(delay_seconds)},
        )

    def due_scheduled(self) -> list[IntentRow]:
        """Scheduled intents whose window has passed, oldest id first."""
        cur = self._live().execute(
            "SELECT * FROM intents WHERE state = 'SCHEDULED' AND scheduled_for <= ?"
            " ORDER BY intent_id",
            (self.now,),
        )
        names = [d[0] for d in cur.description]
        return [_intent_row(dict(zip(names, r, strict=True))) for r in cur.fetchall()]

    def insert_receipt(
        self, intent_id: str, *, result: object, external_id: str | None, source: str
    ) -> ReceiptRow:
        """Record proof of a side effect, with its ``receipt_recorded`` event.

        The result is redacted before it is hashed or stored, and stored only up
        to _RESULT_LIMIT characters. A result with no canonical JSON form is
        hashed by its type.

        Raises:
            StaleStateError: the intent already has a receipt.
        """
        try:
            text: str | None = canonical_json(self._redactor.redact(result))
            digest = hashlib.sha256(text.encode()).hexdigest()  # type: ignore[union-attr]
        except (CanonicalizationError, TypeError, ValueError):
            text = None
            digest = hashlib.sha256(f"unencodable:{type(result).__name__}".encode()).hexdigest()
        if text is not None and len(text) > _RESULT_LIMIT:
            text = None
        external = self._redactor.redact_text(external_id) if external_id is not None else None
        try:
            self._live().execute(
                "INSERT INTO receipts (intent_id, result_hash, result_redacted, external_id,"
                " source, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (intent_id, digest, text, external, source, self.now),
            )
        except sqlite3.IntegrityError as exc:
            raise StaleStateError(f"intent {intent_id} already has a receipt") from exc
        row = self.get_intent(intent_id)
        self._append(
            "receipt_recorded",
            {"result_hash": digest, "external_id": external, "source": source},
            intent_id=intent_id,
            run_id=row.run_id if row is not None else None,
            verbatim=True,
        )
        return ReceiptRow(intent_id, digest, text, external, source, self.now)

    def get_receipt(self, intent_id: str) -> ReceiptRow | None:
        """The receipt of an intent, or None."""
        found = (
            self._live()
            .execute(
                "SELECT intent_id, result_hash, result_redacted, external_id, source, created_at"
                " FROM receipts WHERE intent_id = ?",
                (intent_id,),
            )
            .fetchone()
        )
        return ReceiptRow(*found) if found is not None else None

    def create_approval(self, intent_id: str, *, ttl_seconds: float) -> ApprovalRow:
        """Ask for a human decision on one intent, bound to its intent hash."""
        row = self.get_intent(intent_id)
        if row is None:
            raise StaleStateError(f"intent {intent_id} does not exist")
        approval_id = new_ulid()
        expires = self._later(ttl_seconds)
        self._live().execute(
            "INSERT INTO approvals (approval_id, intent_id, intent_hash, status, requested_at,"
            " expires_at) VALUES (?, ?, ?, 'pending', ?, ?)",
            (approval_id, intent_id, row.intent_hash, self.now, expires),
        )
        self._append(
            "approval_requested",
            {"approval_id": approval_id, "intent_hash": row.intent_hash, "expires_at": expires},
            intent_id=intent_id,
            run_id=row.run_id,
            verbatim=True,
        )
        return ApprovalRow(approval_id, intent_id, row.intent_hash, "pending", self.now, expires,
                           None, None, None)  # fmt: skip

    def get_approval(self, approval_id: str) -> ApprovalRow | None:
        """One approval, or None."""
        found = (
            self._live()
            .execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,))
            .fetchone()
        )
        return ApprovalRow(*found) if found is not None else None

    def approval_for_intent(self, intent_id: str) -> ApprovalRow | None:
        """The latest approval requested for an intent, or None."""
        found = (
            self._live()
            .execute(
                "SELECT * FROM approvals WHERE intent_id = ? ORDER BY requested_at DESC,"
                " approval_id DESC LIMIT 1",
                (intent_id,),
            )
            .fetchone()
        )
        return ApprovalRow(*found) if found is not None else None


def _apply_change(
    expected: dict[str, dict[str, object]], event: Event, payload: dict[str, object]
) -> str | None:
    """Apply a transition or lease extension to the facts replayed so far."""
    is_move = event.kind in _TRANSITION_KINDS and "to" in payload
    if not is_move and event.kind != "lease_extended":
        return None
    facts = expected.get(str(event.intent_id))
    if facts is None:
        return f"event {event.seq} changes {event.intent_id} before it exists"
    if not is_move:
        facts["lease_expires_at"] = payload.get("lease_expires_at")
        return None
    if payload.get("from") != facts["state"] or not can_transition(
        IntentState(str(payload["from"])), IntentState(str(payload["to"]))
    ):
        return f"event {event.seq} records an impossible move"
    facts["state"] = payload["to"]
    for name in _UPDATABLE_ORDER:
        if name in payload:
            facts[name] = payload[name]
    return None


def _intent_row(data: dict[str, object]) -> IntentRow:
    data["state"] = IntentState(str(data["state"]))
    data["args_exact"] = bool(data["args_exact"])
    return IntentRow(**data)  # type: ignore[arg-type]


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
    return _intent_row(data)


def _check_amount(value: float) -> None:
    if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise StorageError(f"budget amount must be a positive finite number, not {value!r}")


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

    def __init__(
        self,
        conn: sqlite3.Connection,
        redactor: Redactor,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Wrap a connection. Use ``SQLiteStorage.open()`` instead."""
        self._conn = conn
        self._redactor = redactor
        self._clock = clock
        self._genesis = ""

    @classmethod
    def open(
        cls,
        path: str | Path,
        redactor: Redactor,
        *,
        busy_timeout_ms: int = BUSY_TIMEOUT_MS,
        any_thread: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> SQLiteStorage:
        """Open (or create) a ledger file, apply pending migrations and return it.

        Safe to call from many threads and processes at once on a new file.
        One storage object must still be used by one thread at a time;
        ``any_thread=True`` only allows that thread to differ from the opener
        (for example, closing a worker thread's connection from the main thread).

        ``clock`` replaces the database clock (``Transaction.now``) with a
        function returning an aware datetime. It exists for deterministic
        simulation tests; leave it unset everywhere else.

        Raises:
            StorageError: the file cannot be opened or migrated, or its schema is
                newer than this version of Arbitr knows.
        """
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(
                str(path),
                isolation_level=None,
                timeout=busy_timeout_ms / 1000,
                check_same_thread=not any_thread,
            )
            conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
            _enable_wal(conn, busy_timeout_ms)
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("PRAGMA foreign_keys = ON")
            storage = cls(conn, redactor, clock)
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
            tx = Transaction(conn, self._redactor, self._genesis, self._clock)
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
        problem = (
            self._check_intents()
            or self._check_budgets()
            or self._check_reservations()
            or self._check_runs()
            or self._check_receipts()
            or self._check_approvals()
        )
        if problem:
            return VerifyResult(ok=False, checked=chain.checked, reason=problem)
        return chain

    def _check_receipts(self) -> str | None:
        """Every receipt must match its receipt_recorded event, and the other way round."""
        recorded: dict[str, tuple[object, ...]] = {}
        for event in self.events():
            if event.kind == "receipt_recorded" and event.intent_id is not None:
                payload = json.loads(event.payload)
                recorded[event.intent_id] = (
                    payload.get("result_hash"),
                    payload.get("external_id"),
                    payload.get("source"),
                )
        cur = self._conn.execute("SELECT intent_id, result_hash, external_id, source FROM receipts")
        for intent_id, *values in cur:
            if recorded.pop(intent_id, None) != tuple(values):
                return f"receipt for intent {intent_id} does not match its recorded event"
        if recorded:
            return f"intent {sorted(recorded)[0]} has a receipt event but no receipt"
        return None

    def _check_approvals(self) -> str | None:
        """Every approval request must match its approval_requested event."""
        recorded: dict[str, tuple[object, ...]] = {}
        for event in self.events():
            if event.kind == "approval_requested":
                payload = json.loads(event.payload)
                recorded[str(payload.get("approval_id"))] = (
                    event.intent_id,
                    payload.get("intent_hash"),
                    payload.get("expires_at"),
                )
        cur = self._conn.execute(
            "SELECT approval_id, intent_id, intent_hash, expires_at FROM approvals"
        )
        for approval_id, *values in cur:
            if recorded.pop(approval_id, None) != tuple(values):
                return f"approval {approval_id} does not match its recorded event"
        if recorded:
            return f"approval {sorted(recorded)[0]} has an event but no record"
        return None

    def _check_runs(self) -> str | None:
        """Every run row must match its run_started event and its latest taint."""
        expected: dict[str, dict[str, object]] = {}
        for event in self.events():
            if event.run_id is None:
                continue
            payload = json.loads(event.payload)
            if event.kind == "run_started":
                expected[event.run_id] = {
                    "principal": payload.get("principal"),
                    "agent_id": payload.get("agent_id"),
                    "mode": payload.get("mode"),
                    "parent_run_id": payload.get("parent_run_id"),
                    "scopes": canonical_json(payload.get("scopes") or []),
                    "scope": canonical_json(payload["scope"]) if payload.get("scope") else None,
                    "taint": canonical_json(payload.get("taint") or Taint().to_dict()),
                }
            elif event.kind == "taint_added" and event.run_id in expected:
                expected[event.run_id]["taint"] = canonical_json(payload.get("taint"))
        cur = self._conn.execute(
            "SELECT run_id, principal, agent_id, mode, parent_run_id, scopes, scope, taint"
            " FROM runs"
        )
        names = ["principal", "agent_id", "mode", "parent_run_id", "scopes", "scope", "taint"]
        for run_id, *values in cur:
            facts = expected.pop(run_id, None)
            if facts is None:
                return f"run {run_id} has no run_started event"
            for name, value in zip(names, values, strict=True):
                if value != facts[name]:
                    return f"run {run_id} {name} does not match its recorded events"
        if expected:
            return f"run {sorted(expected)[0]} has events but its record is missing"
        return None

    def _check_budgets(self) -> str | None:
        """Every budget counter must equal its reservations minus its releases."""
        expected: dict[str, float] = {}
        for event in self.events():
            if event.kind in {"budget_reserved", "budget_released"}:
                payload = json.loads(event.payload)
                sign = 1.0 if event.kind == "budget_reserved" else -1.0
                key = str(payload["scope_key"])
                expected[key] = expected.get(key, 0.0) + sign * float(payload["amount"])
        for key, value in self._conn.execute("SELECT scope_key, value FROM budget_counters"):
            if not math.isclose(float(value), expected.pop(key, 0.0), abs_tol=1e-9):
                return f"budget counter {key} does not match its recorded reservations"
        for key, value in expected.items():
            if not math.isclose(value, 0.0, abs_tol=1e-9):
                return f"budget counter {key} is missing but has recorded reservations"
        return None

    def _check_reservations(self) -> str | None:
        """Every reservation row must equal its intent's reserved minus released events."""
        expected: dict[tuple[str, str], float] = {}
        for event in self.events():
            if event.intent_id is None or event.kind not in {"budget_reserved", "budget_released"}:
                continue
            payload = json.loads(event.payload)
            sign = 1.0 if event.kind == "budget_reserved" else -1.0
            slot = (event.intent_id, str(payload["scope_key"]))
            expected[slot] = expected.get(slot, 0.0) + sign * float(payload["amount"])
        rows = self._conn.execute("SELECT intent_id, scope_key, amount FROM reservations")
        for intent_id, key, amount in rows:
            if not math.isclose(float(amount), expected.pop((intent_id, key), 0.0), abs_tol=1e-9):
                return f"reservation of {key} by intent {intent_id} does not match its events"
        for (intent_id, key), value in expected.items():
            if not math.isclose(value, 0.0, abs_tol=1e-9):
                return f"reservation of {key} by intent {intent_id} is missing"
        return None

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
                    "args_exact": bool(payload.get("args_exact", False)),
                }
            else:
                problem = _apply_change(expected, event, payload)
                if problem:
                    return expected, problem
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
            yield _intent_row(dict(zip(names, row, strict=True)))

    def intent_count(self) -> int:
        """Number of stored intents."""
        return int(self._conn.execute("SELECT COUNT(*) FROM intents").fetchone()[0])


def _split_sql(script: str) -> list[str]:
    """Split a migration into statements. Migrations contain no semicolons in strings."""
    return [s.strip() for s in script.split(";") if s.strip()]


def decode_args(row: IntentRow) -> object:
    """Parse the stored (redacted) arguments of an intent."""
    return json.loads(row.args_redacted)
