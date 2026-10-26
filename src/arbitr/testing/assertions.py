"""Assertions about what an agent did, read from the ledger.

Each takes the run to check (the ``arbitr_run`` fixture, or any ``TestRun``)
and fails with a message that lists the actions involved.

Example::

    def test_agent_never_drops_tables(arbitr_run):
        my_agent.handle("clean up the database")
        assert_no_effect(arbitr_run, "destructive")
        assert_denied(arbitr_run, tool="db.execute", rule="no-destructive-sql")
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from arbitr.core.states import IntentState

if TYPE_CHECKING:
    from collections.abc import Mapping

    from arbitr.executor import Ledger
    from arbitr.storage.sqlite import IntentRow

__all__ = [
    "TestRun",
    "assert_denied",
    "assert_exactly_once",
    "assert_needs_approval",
    "assert_no_effect",
    "assert_not_run",
]


@dataclass(frozen=True)
class TestRun:
    """A run to make assertions about: the ledger and the run id."""

    __test__ = False  # not a test class, whatever pytest thinks of the name

    ledger: Ledger
    run_id: str

    def intents(self, tool: str | None = None) -> list[IntentRow]:
        """The run's intents (for one tool), oldest first."""
        rows = self.ledger.find_intents(run_id=self.run_id, tool=tool, limit=100_000)
        return sorted(rows, key=lambda row: (row.created_at, row.intent_id))

    def executions(self, row: IntentRow) -> int:
        """How many times the ledger started this intent's tool."""
        return sum(1 for e in self.ledger.intent_events(row.intent_id) if e.kind == "executing")


def assert_no_effect(run: TestRun, effect: str) -> None:
    """No action with this effect ran, or may have run, in the run.

    Effects are the ones Arbitr settled on, after reading the arguments: an
    ``rm -rf`` through a tool declared as a write counts as destructive.
    """
    ran = [row for row in run.intents() if row.effect == effect and run.executions(row)]
    if ran:
        raise AssertionError(f"{len(ran)} {effect} action(s) ran:\n{_list(ran)}")


def assert_not_run(run: TestRun, tool: str, args: Mapping[str, object] | None = None) -> None:
    """The tool never ran in the run (for calls with these arguments, if given)."""
    ran = [row for row in _matching(run, tool, args) if run.executions(row)]
    if ran:
        raise AssertionError(f"{tool} ran {len(ran)} time(s):\n{_list(ran)}")


def assert_denied(
    run: TestRun,
    tool: str | None = None,
    rule: str | None = None,
    args: Mapping[str, object] | None = None,
) -> None:
    """At least one matching action was denied, and none of the denied ones ran."""
    _assert_stopped(run, IntentState.DENIED, "denied", tool=tool, rule=rule, args=args)


def assert_needs_approval(
    run: TestRun,
    tool: str | None = None,
    rule: str | None = None,
    args: Mapping[str, object] | None = None,
) -> None:
    """At least one matching action is waiting for a human, and it has not run."""
    _assert_stopped(
        run, IntentState.PENDING_APPROVAL, "waiting for approval", tool=tool, rule=rule, args=args
    )


def assert_exactly_once(run: TestRun, tool: str, args: Mapping[str, object] | None = None) -> None:
    """The tool's side effect happened exactly once in the run, and succeeded.

    Retries that got the stored receipt back do not count. With ``args``,
    only calls whose arguments include those values count.
    """
    rows = _matching(run, tool, args)
    started = sum(run.executions(row) for row in rows)
    done = [row for row in rows if row.state is IntentState.SUCCEEDED]
    if started != 1 or len(done) != 1:
        found = _list(rows) if rows else "  (no calls)"
        raise AssertionError(
            f"expected {tool} to run exactly once and succeed; it started {started} time(s)"
            f" and succeeded {len(done)} time(s):\n{found}"
        )


def _assert_stopped(  # noqa: PLR0913 - the filters are independent
    run: TestRun,
    state: IntentState,
    what: str,
    *,
    tool: str | None,
    rule: str | None,
    args: Mapping[str, object] | None,
) -> None:
    rows = _matching(run, tool, args)
    stopped = [r for r in rows if r.state is state and (rule is None or r.decision_rule == rule)]
    if not stopped:
        wanted = " ".join(p for p in (tool and f"tool={tool}", rule and f"rule={rule}") if p)
        found = _list(rows) if rows else "  (no matching calls)"
        raise AssertionError(f"no action {what}{f' ({wanted})' if wanted else ''}:\n{found}")
    ran = [row for row in stopped if run.executions(row)]
    if ran:  # pragma: no cover, the ledger never runs a stopped action
        raise AssertionError(f"actions {what} still ran:\n{_list(ran)}")


def _matching(run: TestRun, tool: str | None, args: Mapping[str, object] | None) -> list[IntentRow]:
    rows = run.intents(tool)
    if args is None:
        return rows
    return [row for row in rows if _has_args(row, args)]


def _has_args(row: IntentRow, wanted: Mapping[str, object]) -> bool:
    try:
        stored = json.loads(row.args_redacted)
    except ValueError:
        return False
    return isinstance(stored, dict) and all(stored.get(k) == v for k, v in wanted.items())


def _list(rows: list[IntentRow]) -> str:
    lines = []
    for row in rows:
        rule = f", rule {row.decision_rule}" if row.decision_rule else ""
        lines.append(
            f"  - {row.tool} ({row.effect}) {row.state.value}{rule}: {row.args_redacted[:200]}"
        )
    return "\n".join(lines)
