"""The intent state machine, as an explicit transition table.

Every state change of an intent goes through ``check_transition``. A change
that is not in ``TRANSITIONS`` is a bug and raises ``IllegalTransitionError``.
The same table is written in the TLA+ model (formal/IntentLifecycle.tla), and a
test fails if the two ever differ.

Example:
    >>> can_transition(IntentState.PROPOSED, IntentState.APPROVED)
    True
    >>> can_transition(IntentState.DENIED, IntentState.EXECUTING)
    False
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from arbitr.core.errors import IllegalTransitionError


class IntentState(StrEnum):
    """Lifecycle states of an action intent."""

    PROPOSED = "PROPOSED"
    DENIED = "DENIED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    COMPENSATED = "COMPENSATED"
    SCHEDULED = "SCHEDULED"
    CANCELLED = "CANCELLED"


S = IntentState

TRANSITIONS: Final[frozenset[tuple[IntentState, IntentState]]] = frozenset(
    {
        (S.PROPOSED, S.DENIED),
        (S.PROPOSED, S.PENDING_APPROVAL),
        (S.PROPOSED, S.APPROVED),  # allowed by the gate without a human
        (S.PENDING_APPROVAL, S.APPROVED),
        (S.PENDING_APPROVAL, S.REJECTED),
        (S.PENDING_APPROVAL, S.EXPIRED),
        (S.APPROVED, S.EXECUTING),
        (S.EXECUTING, S.SUCCEEDED),
        (S.EXECUTING, S.FAILED),
        (S.EXECUTING, S.UNKNOWN),  # crash, expired lease or inconclusive probe
        (S.FAILED, S.EXECUTING),  # retry with attempt + 1
        (S.UNKNOWN, S.SUCCEEDED),  # a probe found the receipt
        (S.UNKNOWN, S.EXECUTING),  # an operator or policy chose to retry
        (S.UNKNOWN, S.FAILED),
        (S.SUCCEEDED, S.COMPENSATED),
        (S.APPROVED, S.SCHEDULED),  # allowed with a delay: a cancel window
        (S.SCHEDULED, S.EXECUTING),  # the window passed
        (S.SCHEDULED, S.CANCELLED),  # a human or a breaker cancelled it in time
    }
)
"""Every legal (from, to) pair. Anything else is a bug."""

TERMINAL: Final[frozenset[IntentState]] = frozenset(
    {S.DENIED, S.REJECTED, S.EXPIRED, S.COMPENSATED, S.CANCELLED}
)
"""States nothing ever leaves."""


def can_transition(current: IntentState, target: IntentState) -> bool:
    """Return whether ``current -> target`` is a legal transition.

    Example:
        >>> can_transition(IntentState.UNKNOWN, IntentState.SUCCEEDED)
        True
    """
    return (current, target) in TRANSITIONS


def check_transition(current: IntentState, target: IntentState) -> None:
    """Raise ``IllegalTransitionError`` unless ``current -> target`` is legal.

    Example:
        >>> check_transition(IntentState.SUCCEEDED, IntentState.EXECUTING)
        Traceback (most recent call last):
        ...
        arbitr.core.errors.IllegalTransitionError: illegal intent transition SUCCEEDED -> EXECUTING
    """
    if not can_transition(current, target):
        raise IllegalTransitionError(f"illegal intent transition {current} -> {target}")


def successors(state: IntentState) -> frozenset[IntentState]:
    """Return every state reachable from ``state`` in one legal step.

    Example:
        >>> sorted(s.value for s in successors(IntentState.PENDING_APPROVAL))
        ['APPROVED', 'EXPIRED', 'REJECTED']
    """
    return frozenset(target for current, target in TRANSITIONS if current == state)
