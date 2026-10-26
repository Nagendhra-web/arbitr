"""Read queries for operators: runs, filtered intents and one intent's history."""

from __future__ import annotations

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

KEY = b"storage-queries!" * 2
S = IntentState


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SQLiteStorage]:
    with SQLiteStorage.open(tmp_path / "ledger.db", Redactor(KEY)) as storage:
        with storage.transaction() as tx:
            tx.insert_run("r1", "alice", "bot")
            tx.insert_run("r2", "bob", "bot")
            for run, tool, n in (("r1", "payments.refund", 3), ("r2", "email.send", 2)):
                spec = ToolSpec(name=tool, effect="write")
                for i in range(n):
                    intent = build_intent(spec, {"i": i}, run_id=run, principal="alice")
                    tx.insert_intent(intent)
                    if i == 0:
                        tx.transition(intent.intent_id, S.DENIED, expected=S.PROPOSED)
        yield storage


def test_runs_are_listed_newest_first(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        runs = tx.runs(limit=10)
        assert [r.run_id for r in runs] == ["r2", "r1"]
        assert [r.run_id for r in tx.runs(limit=1)] == ["r2"]


def test_intents_can_be_filtered(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        assert len(tx.find_intents()) == 5
        assert len(tx.find_intents(run_id="r1")) == 3
        assert len(tx.find_intents(tool="email.send")) == 2
        assert len(tx.find_intents(state=S.DENIED)) == 2
        assert len(tx.find_intents(run_id="r1", state=S.PROPOSED, limit=1)) == 1
        assert tx.find_intents(since="2999-01-01T00:00:00.000Z") == []


def test_an_intents_history_is_its_own_events(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        (denied, *_) = tx.find_intents(run_id="r1", state=S.DENIED)
        kinds = [e.kind for e in tx.intent_events(denied.intent_id)]
    assert kinds == ["intent_created", "denied"]
