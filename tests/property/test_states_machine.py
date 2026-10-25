"""Stateful property test: random operation sequences never reach an illegal state."""

from __future__ import annotations

from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from arbitr.core.errors import IllegalTransitionError
from arbitr.core.states import TERMINAL, IntentState, can_transition, check_transition


class IntentLifecycle(RuleBasedStateMachine):
    """Drive one intent with random requested transitions, legal or not."""

    def __init__(self) -> None:
        super().__init__()
        self.state = IntentState.PROPOSED
        self.history: list[IntentState] = [self.state]
        self.executions = 0

    @rule(wanted=st.sampled_from(list(IntentState)))
    def request(self, wanted: IntentState) -> None:
        before = self.state
        try:
            check_transition(before, wanted)
        except IllegalTransitionError:
            assert not can_transition(before, wanted)
            assert self.state == before  # a refused change leaves the state alone
            return
        self.state = wanted
        self.history.append(wanted)
        if wanted == IntentState.EXECUTING:
            self.executions += 1

    @invariant()
    def every_step_in_the_history_is_legal(self) -> None:
        for a, b in zip(self.history, self.history[1:], strict=False):
            assert can_transition(a, b)

    @invariant()
    def terminal_states_are_final(self) -> None:
        for i, s in enumerate(self.history[:-1]):
            assert s not in TERMINAL, f"left terminal state {s} at step {i}"

    @invariant()
    def execution_follows_an_allow_or_approval(self) -> None:
        if self.executions:
            assert IntentState.APPROVED in self.history


TestIntentLifecycle = IntentLifecycle.TestCase
