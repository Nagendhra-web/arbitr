"""Stateful test of budget counters against a simple model."""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from arbitr.core.errors import StorageError
from arbitr.core.redact import Redactor
from arbitr.storage.sqlite import SQLiteStorage

KEYS = ["k:a", "k:b", "k:c"]
LIMIT = 50.0


class BudgetMachine(RuleBasedStateMachine):
    """Random reserves and releases; the ledger must match the model exactly."""

    def __init__(self) -> None:
        super().__init__()
        self.tmp = tempfile.TemporaryDirectory()
        self.db = SQLiteStorage.open(
            Path(self.tmp.name) / "b.db", Redactor(b"budget-machine-k" * 2)
        )
        self.model = dict.fromkeys(KEYS, 0.0)

    @rule(key=st.sampled_from(KEYS), amount=st.integers(1, 30))
    def reserve(self, key: str, amount: int) -> None:
        with self.db.transaction() as tx:
            ok = tx.reserve_budget(key, amount, LIMIT)
        assert ok == (self.model[key] + amount <= LIMIT)
        if ok:
            self.model[key] += amount

    @rule(key=st.sampled_from(KEYS), amount=st.integers(1, 30))
    def release(self, key: str, amount: int) -> None:
        try:
            with self.db.transaction() as tx:
                tx.release_budget(key, amount)
        except StorageError:
            assert amount > self.model[key]
            return
        assert amount <= self.model[key]
        self.model[key] -= amount

    @invariant()
    def counters_match_and_stay_in_bounds(self) -> None:
        with self.db.transaction() as tx:
            counters = tx.budget_counters(KEYS)
        assert counters == self.model
        assert all(0 <= v <= LIMIT for v in counters.values())

    @invariant()
    def ledger_verifies(self) -> None:
        assert self.db.verify().ok

    def teardown(self) -> None:
        self.db.close()
        self.tmp.cleanup()


BudgetMachine.TestCase.settings = settings(max_examples=30, stateful_step_count=25, deadline=None)
TestBudgetMachine = BudgetMachine.TestCase
