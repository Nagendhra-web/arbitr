"""The intent state machine and its agreement with the TLA+ model."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from arbitr.core.errors import IllegalTransitionError
from arbitr.core.states import (
    TERMINAL,
    TRANSITIONS,
    IntentState,
    can_transition,
    check_transition,
    successors,
)

TLA = Path(__file__).resolve().parents[3] / "formal" / "IntentLifecycle.tla"


def tla_block(name: str) -> str:
    text = TLA.read_text(encoding="utf-8")
    match = re.search(rf"\\\* BEGIN {name}\n(.*?)\\\* END {name}", text, re.S)
    assert match, f"BEGIN/END {name} markers missing from {TLA.name}"
    return match.group(1)


def test_python_table_matches_the_tla_model() -> None:
    """The model checker verifies the TLA+ list. This keeps the code in step with it."""
    pairs = re.findall(r'<<"([A-Z_]+)",\s*"([A-Z_]+)">>', tla_block("TRANSITIONS"))
    assert pairs, "no transitions parsed from the TLA+ model"
    tla = {(IntentState(a), IntentState(b)) for a, b in pairs}
    assert len(pairs) == len(tla), "duplicate transition in the TLA+ model"
    assert tla == set(TRANSITIONS)


def test_tla_model_lists_the_same_states() -> None:
    text = TLA.read_text(encoding="utf-8")
    match = re.search(r"States == \{(.*?)\}", text, re.S)
    assert match
    assert set(re.findall(r'"([A-Z_]+)"', match.group(1))) == {s.value for s in IntentState}


def test_tla_model_lists_the_same_terminal_states() -> None:
    text = TLA.read_text(encoding="utf-8")
    match = re.search(r"Terminal == \{(.*?)\}", text, re.S)
    assert match
    assert set(re.findall(r'"([A-Z_]+)"', match.group(1))) == {s.value for s in TERMINAL}


@pytest.mark.parametrize(("current", "target"), sorted(TRANSITIONS))
def test_every_listed_transition_is_allowed(current: IntentState, target: IntentState) -> None:
    assert can_transition(current, target)
    check_transition(current, target)


ILLEGAL = sorted((a, b) for a in IntentState for b in IntentState if (a, b) not in TRANSITIONS)


@pytest.mark.parametrize(("current", "target"), ILLEGAL)
def test_every_other_pair_raises(current: IntentState, target: IntentState) -> None:
    assert not can_transition(current, target)
    with pytest.raises(IllegalTransitionError, match=f"{current} -> {target}"):
        check_transition(current, target)


@pytest.mark.parametrize("state", sorted(TERMINAL))
def test_terminal_states_have_no_successors(state: IntentState) -> None:
    assert successors(state) == frozenset()


def test_non_terminal_states_can_move() -> None:
    for state in set(IntentState) - TERMINAL:
        assert successors(state), f"{state} is a dead end but not terminal"


def test_no_self_loops() -> None:
    assert all(a != b for a, b in TRANSITIONS)


def test_every_state_is_reachable_from_proposed() -> None:
    seen = {IntentState.PROPOSED}
    frontier = [IntentState.PROPOSED]
    while frontier:
        for nxt in successors(frontier.pop()):
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    assert seen == set(IntentState)


def test_execution_needs_an_allow_or_an_approval_first() -> None:
    """Nothing reaches EXECUTING straight from PROPOSED or PENDING_APPROVAL."""
    assert {a for a, b in TRANSITIONS if b == IntentState.EXECUTING} == {
        IntentState.APPROVED,
        IntentState.SCHEDULED,  # only reachable from APPROVED
        IntentState.FAILED,
        IntentState.UNKNOWN,
    }
    assert {a for a, b in TRANSITIONS if b == IntentState.SCHEDULED} == {IntentState.APPROVED}


def test_error_code() -> None:
    assert IllegalTransitionError.code == "illegal_transition"
