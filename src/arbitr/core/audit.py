"""The tamper-evident audit chain.

Every state change writes one event. Each event's hash covers the previous
event's hash, so changing, deleting or reordering any event breaks every link
after it, and ``verify_chain`` reports the first broken one.

The hash is SHA-256 over the canonical JSON array
``[prev_hash, kind, intent_id, run_id, payload, created_at]``. A canonical
array, unlike plain concatenation, cannot be read two ways, and covering the
ids means an event cannot be moved to another intent or run unnoticed.

Limit, stated plainly: someone who can rewrite the whole database can rebuild
a consistent chain, and can drop events from the end. Signed checkpoints close
that gap; until then, the chain proves internal consistency only.

Example:
    >>> g = genesis_hash("install-1")
    >>> t = "2026-10-25T00:00:00.000Z"
    >>> h1 = event_hash(g, "intent_created", "{}", t, intent_id=None, run_id=None)
    >>> e1 = Event(1, None, None, "intent_created", "{}", g, h1, "2026-10-25T00:00:00.000Z")
    >>> verify_chain([e1], g).ok
    True
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from arbitr.core.canonical import sha256_hex

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


def genesis_hash(install_id: str) -> str:
    """The ``prev_hash`` of the first event, derived from the install id.

    Example:
        >>> len(genesis_hash("x"))
        64
    """
    return hashlib.sha256(f"arbitr:genesis:{install_id}".encode()).hexdigest()


def event_hash(  # noqa: PLR0913, every field of the event is covered
    prev_hash: str,
    kind: str,
    payload: str,
    created_at: str,
    *,
    intent_id: str | None,
    run_id: str | None,
) -> str:
    """Hash of one event, chained to the previous one. Covers every stored field."""
    return sha256_hex([prev_hash, kind, intent_id, run_id, payload, created_at])


@dataclass(frozen=True)
class Event:
    """One row of the audit chain. ``payload`` is canonical JSON, already redacted."""

    seq: int
    intent_id: str | None
    run_id: str | None
    kind: str
    payload: str
    prev_hash: str
    hash: str
    created_at: str


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of walking the chain."""

    ok: bool
    checked: int
    broken_seq: int | None = None
    reason: str | None = None

    def describe(self) -> str:
        """One plain-English line for the CLI and logs.

        Example:
            >>> VerifyResult(ok=True, checked=3).describe()
            'Audit chain verified: 3 events, no broken links.'
        """
        if self.ok:
            return f"Audit chain verified: {self.checked} events, no broken links."
        if self.broken_seq is None:
            return f"Ledger does not match its audit chain: {self.reason}."
        return f"Audit chain broken at event {self.broken_seq}: {self.reason}."


def verify_chain(events: Iterable[Event], genesis: str) -> VerifyResult:
    """Walk events in sequence order and report the first broken link."""
    prev = genesis
    last_seq = 0
    checked = 0
    for event in events:
        if event.seq <= last_seq:
            return VerifyResult(
                ok=False, checked=checked, broken_seq=event.seq, reason="events are out of order"
            )
        if event.prev_hash != prev:
            return VerifyResult(
                ok=False,
                checked=checked,
                broken_seq=event.seq,
                reason="it does not link to the event before it",
            )
        expected = event_hash(
            event.prev_hash,
            event.kind,
            event.payload,
            event.created_at,
            intent_id=event.intent_id,
            run_id=event.run_id,
        )
        if event.hash != expected:
            return VerifyResult(
                ok=False,
                checked=checked,
                broken_seq=event.seq,
                reason="its contents do not match its hash",
            )
        prev = event.hash
        last_seq = event.seq
        checked += 1
    return VerifyResult(ok=True, checked=checked)


def export_jsonl(events: Iterable[Event]) -> Iterator[str]:
    """Yield one JSON line per event, for shipping to a SIEM.

    Payloads are already redacted, so the export contains no secrets.
    """
    for event in events:
        yield json.dumps(asdict(event), sort_keys=True, ensure_ascii=False)
