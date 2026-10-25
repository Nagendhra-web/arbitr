"""Stateful test of the real storage: random transitions, many of them stale.

After every step the database must agree with a simple model, every recorded
event must be a legal move, and the audit chain plus the intent cross-check
must verify.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule

from arbitr.core.errors import IllegalTransitionError, StaleStateError
from arbitr.core.intent import build_intent
from arbitr.core.redact import Redactor
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState, can_transition
from arbitr.storage.sqlite import SQLiteStorage

SPEC = ToolSpec(name="t.x", effect="write")
STATES = list(IntentState)


class StorageMachine(RuleBasedStateMachine):
    """A model of intents (state and attempt) next to the real ledger."""

    def __init__(self) -> None:
        super().__init__()
        self.tmp = tempfile.TemporaryDirectory()
        self.db = SQLiteStorage.open(
            Path(self.tmp.name) / "l.db", Redactor(b"machine-key-0123" * 2)
        )
        self.model: dict[str, tuple[IntentState, int]] = {}
        self.n = 0

    @initialize()
    def start_run(self) -> None:
        with self.db.transaction() as tx:
            tx.insert_run("r", "alice", "bot")

    @rule()
    def add_intent(self) -> None:
        self.n += 1
        intent = build_intent(SPEC, {"n": self.n}, run_id="r", principal="alice")
        with self.db.transaction() as tx:
            tx.insert_intent(intent)
        self.model[intent.intent_id] = (IntentState.PROPOSED, 0)

    @precondition(lambda self: bool(self.model))
    @rule(
        pick=st.integers(min_value=0),
        target_state=st.sampled_from(STATES),
        claimed=st.sampled_from(STATES),
        stale_attempt=st.booleans(),
    )
    def move(
        self, pick: int, target_state: IntentState, claimed: IntentState, stale_attempt: bool
    ) -> None:
        intent_id = sorted(self.model)[pick % len(self.model)]
        actual, attempt = self.model[intent_id]
        fence = attempt - 1 if stale_attempt else attempt
        bump = target_state == IntentState.EXECUTING
        fields = {"attempt": attempt + 1} if bump else {}
        try:
            with self.db.transaction() as tx:
                tx.transition(
                    intent_id, target_state, expected=claimed, fields=fields, expected_attempt=fence
                )
        except IllegalTransitionError:
            assert not can_transition(claimed, target_state)
            return
        except StaleStateError:
            assert claimed != actual or stale_attempt
            return
        # It succeeded, so the claim and fence must have been right.
        assert claimed == actual
        assert not stale_attempt
        assert can_transition(actual, target_state)
        self.model[intent_id] = (target_state, attempt + 1 if bump else attempt)

    @invariant()
    def database_matches_model(self) -> None:
        with self.db.transaction() as tx:
            for intent_id, (state, attempt) in self.model.items():
                row = tx.get_intent(intent_id)
                assert row is not None
                assert (row.state, row.attempt) == (state, attempt)

    @invariant()
    def every_event_is_a_legal_move(self) -> None:
        for event in self.db.events():
            payload = json.loads(event.payload)
            if "to" in payload:
                assert can_transition(IntentState(payload["from"]), IntentState(payload["to"]))

    @invariant()
    def ledger_verifies(self) -> None:
        result = self.db.verify()
        assert result.ok, result.describe()

    def teardown(self) -> None:
        self.db.close()
        self.tmp.cleanup()


StorageMachine.TestCase.settings = settings(max_examples=40, stateful_step_count=30, deadline=None)
TestStorageMachine = StorageMachine.TestCase
