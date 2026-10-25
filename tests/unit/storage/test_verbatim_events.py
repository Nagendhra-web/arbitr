"""Events mirror their rows exactly, so ids and hashes that look like card numbers verify.

Hashes, ULIDs, worker ids and budget keys can contain digit runs that pass the
Luhn check. The redactor must not rewrite storage's own fields in events, or
verify would report a healthy ledger as tampered.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest

from arbitr.core.intent import build_intent
from arbitr.core.redact import Redactor
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.storage.sqlite import SQLiteStorage

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"verbatim-events!" * 2
SPEC = ToolSpec(name="payments.refund", effect="financial")
CARD = "4111111111111111"  # a test card number that passes the Luhn check
S = IntentState


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SQLiteStorage]:
    with SQLiteStorage.open(tmp_path / "ledger.db", Redactor(KEY)) as storage:
        yield storage


def card_like(text: str) -> bool:
    return Redactor(KEY).redact_text(text) != text


def args_with_card_like_hash() -> dict[str, object]:
    for i in range(200_000):
        args = {"order": f"o{i}"}
        if card_like(build_intent(SPEC, args, run_id="r", principal="alice").intent_hash):
            return args
    raise AssertionError("no intent hash with a card-like digit run found")


def events(db: SQLiteStorage, kind: str) -> list[dict[str, object]]:
    return [json.loads(e.payload) for e in db.events() if e.kind == kind]


def test_an_intent_hash_that_looks_like_a_card_verifies(db: SQLiteStorage) -> None:
    intent = build_intent(SPEC, args_with_card_like_hash(), run_id="r", principal="alice")
    with db.transaction() as tx:
        tx.insert_run("r", "alice", "bot")
        tx.insert_intent(intent)
        tx.transition(intent.intent_id, S.PENDING_APPROVAL, expected=S.PROPOSED)
        tx.create_approval(intent.intent_id, ttl_seconds=60)
    assert events(db, "intent_created")[0]["intent_hash"] == intent.intent_hash
    assert events(db, "approval_requested")[0]["intent_hash"] == intent.intent_hash
    assert db.verify().ok


def test_ids_and_keys_that_look_like_cards_verify(db: SQLiteStorage) -> None:
    intent = build_intent(SPEC, {"order": "o1"}, run_id=f"run-{CARD}", principal=f"emp-{CARD}")
    with db.transaction() as tx:
        tx.insert_run(f"run-{CARD}", f"emp-{CARD}", f"agent-{CARD}")
        tx.insert_intent(intent)
        tx.transition(intent.intent_id, S.APPROVED, expected=S.PROPOSED)
        worker = f"w-{CARD}"
        tx.start_execution(intent.intent_id, expected=S.APPROVED, worker=worker, ttl_seconds=60)
        tx.heartbeat(intent.intent_id, worker=worker, attempt=1, ttl_seconds=60)
        assert tx.reserve_budget(f"rule:cap|principal:emp-{CARD}", 5, 100)
    assert db.verify().ok


def test_a_redaction_marker_is_not_redacted_twice(db: SQLiteStorage) -> None:
    """Stored arguments are already redacted; an event must hold the very same text."""
    redactor = Redactor(KEY)
    for i in range(200_000):
        value = hashlib.sha256(str(i).encode()).hexdigest()
        once = redactor.redact({"password": value})
        if redactor.redact(once) != once:
            break
    else:
        pytest.fail("no marker that redacts twice found")
    intent = build_intent(SPEC, {"password": value}, run_id="r", principal="alice")
    with db.transaction() as tx:
        tx.insert_run("r", "alice", "bot")
        row = tx.insert_intent(intent)
    assert json.loads(row.args_redacted) == once
    assert db.verify().ok


def test_free_text_details_are_still_redacted(db: SQLiteStorage) -> None:
    intent = build_intent(SPEC, {"order": "o1"}, run_id="r", principal="alice")
    with db.transaction() as tx:
        tx.insert_run("r", "alice", "bot")
        tx.insert_intent(intent)
        tx.transition(intent.intent_id, S.DENIED, expected=S.PROPOSED,
                      detail={"note": f"customer card {CARD}"})  # fmt: skip
        tx.append_event("note", {"text": f"card {CARD}"}, intent_id=intent.intent_id)
    assert CARD not in "".join(e.payload for e in db.events())
    assert db.verify().ok
