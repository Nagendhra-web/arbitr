"""The deterministic gate.

``decide`` is a pure function of the gate input, the policy and a snapshot of
budget counters. No model, no I/O, no clock reads: the time comes in with the
input. The same input always gives the same decision, which is what makes
decisions explainable and replayable.

Evaluation:

1. Collect every rule whose ``when`` matches.
2. A budget rule fires only when charging this call would exceed its limit;
   otherwise it contributes a charge to reserve when the action runs. An
   amount that cannot be measured (missing or not a number) fires the rule.
3. ``deny`` beats ``require_approval`` beats ``delay`` beats ``allow``. Among
   equal outcomes the first matching rule in file order is the reason; among
   delays, the longest one (then the first) wins.
4. If nothing matches, the policy default for the effect applies.
5. In shadow mode the decision is recorded but the call is allowed, except
   that matching ``always_enforce`` rules still apply (the strictest of them).

Reasons come only from the policy text, never from argument values, so a
decision can be shown or logged without leaking what the agent sent.
"""

from __future__ import annotations

import fnmatch
import math
from dataclasses import dataclass, field
from datetime import UTC
from typing import TYPE_CHECKING, Final, Literal

from arbitr.core.spec import EFFECT_RANK, Effect
from arbitr.core.taint import Taint
from arbitr.policy import jsonpath
from arbitr.policy.ops import evaluate

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from arbitr.policy.schema import (
        Budget,
        Outcome,
        Policy,
        ResourceCount,
        Rule,
        Verdict,
        When,
    )

__all__ = [
    "RANK",
    "BudgetCharge",
    "Decision",
    "GateInput",
    "ResolvedResource",
    "RuleMatch",
    "Taint",
    "budget_key",
    "decide",
]

RANK: Final[dict[str, int]] = {"allow": 0, "delay": 1, "require_approval": 2, "deny": 3}
OUTSIDE_SCOPE_REASON: Final = "The action is outside the scope declared for this run."


@dataclass(frozen=True)
class ResolvedResource:
    """A resource the action touches, with the tags the policy gave it."""

    id: str | None
    kind: str
    uri: str
    tags: frozenset[str] = frozenset()
    ids: frozenset[str] = frozenset()
    """Every policy resource definition that matched; ``id`` is the first."""


@dataclass(frozen=True)
class GateInput:
    """Everything the gate looks at for one action."""

    tool: str
    effect: Effect
    args: Mapping[str, object]
    principal: str
    agent_id: str
    run_id: str
    now: datetime
    resources: tuple[ResolvedResource, ...] = ()
    taint: Taint = field(default_factory=Taint)
    scopes: frozenset[str] = frozenset()
    outside_scope: bool = False
    outbound_findings: frozenset[str] = frozenset()
    mode: Literal["enforce", "shadow"] | None = None

    def __post_init__(self) -> None:
        """Refuse unknown effects and naive times; keep times in UTC.

        Budget days and hours are UTC, so workers in different time zones
        always charge the same counter.
        """
        if self.effect not in EFFECT_RANK:
            raise ValueError(f"unknown effect {self.effect!r}")
        if self.now.tzinfo is None or self.now.utcoffset() is None:
            raise ValueError("now needs a timezone")
        object.__setattr__(self, "now", self.now.astimezone(UTC))


@dataclass(frozen=True)
class RuleMatch:
    """One rule that matched, and what it asked for."""

    rule_id: str
    outcome: Verdict
    reason: str
    always_enforce: bool = False
    budget: bool = False
    delay_seconds: float = 0.0


@dataclass(frozen=True)
class BudgetCharge:
    """An amount to reserve against a budget when the action runs."""

    rule_id: str
    scope_key: str
    amount: float
    limit: float


@dataclass(frozen=True)
class Decision:
    """What the gate decided and why."""

    outcome: Verdict
    shadow_outcome: Verdict
    rule_id: str
    reason: str
    mode: Literal["enforce", "shadow"]
    matches: tuple[RuleMatch, ...] = ()
    charges: tuple[BudgetCharge, ...] = ()
    delay_seconds: float = 0.0
    """How long a ``delay`` outcome waits before the action runs (0 otherwise)."""
    shadow_rule_id: str = ""
    """The rule enforce mode would have applied (the same as rule_id in enforce mode)."""
    shadow_reason: str = ""

    def explain(self) -> str:
        """Plain-English account of every matching rule and why the winner won."""
        lines = [f"Decision: {self.outcome} by rule {self.rule_id}: {self.reason}"]
        if self.mode == "shadow":
            lines.append(
                f"Shadow mode: enforce mode would have decided {self.shadow_outcome}"
                f" by rule {self.shadow_rule_id}: {self.shadow_reason}"
            )
        if self.matches:
            lines.append("Matching rules, in policy order:")
            lines.extend(
                f"  - {m.rule_id}: {m.outcome}{' (always enforced)' if m.always_enforce else ''}"
                for m in self.matches
            )
            lines.append(
                "Precedence: deny beats require_approval beats delay beats allow; among"
                " equal outcomes the first rule in the policy wins (for delays, the longest)."
            )
        else:
            lines.append("No rule matched, so the policy default for the effect applied.")
        lines.extend(
            f"Budget {c.rule_id}: will reserve {c.amount:g} of {c.limit:g} ({c.scope_key})."
            for c in self.charges
        )
        return "\n".join(lines)


def budget_key(rule_id: str, budget: Budget, inp: GateInput) -> str:
    """Return the counter a budget charges for this input.

    For example ``rule:cap|principal:alice|day:2026-10-25``.
    """
    values = {
        "principal": inp.principal,
        "agent": inp.agent_id,
        "run": inp.run_id,
        "tool": inp.tool,
        "day": inp.now.strftime("%Y-%m-%d"),
        "hour": inp.now.strftime("%Y-%m-%dT%H"),
    }
    parts = (f"{dim}:{_escape(values[dim])}" for dim in budget.scope)
    return "|".join([f"rule:{_escape(rule_id)}", *parts])


def _escape(value: str) -> str:
    """Escape the key separators, so two different inputs never share a counter."""
    return value.replace("%", "%25").replace("|", "%7C").replace(":", "%3A")


def _measure(budget: Budget, args: Mapping[str, object]) -> float | None:
    if budget.count:
        return 1.0
    assert budget.sum_path is not None  # noqa: S101, guaranteed by the schema
    total = 0.0
    found = False
    for _, value in jsonpath.find(args, budget.sum_path):
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None
        if not math.isfinite(float(value)) or value < 0:
            return None
        total += float(value)
        found = True
    return total if found else None


def _window_active(policy: Policy, name: str, now: datetime) -> bool:
    window = policy.windows[name]
    return window.start <= now < window.end


def _tags(inp: GateInput) -> set[str]:
    return {tag for r in inp.resources for tag in r.tags}


def _tool_ok(when: When, inp: GateInput, policy: Policy) -> bool:
    return (when.tool is None or inp.tool == when.tool) and (
        when.tool_glob is None or fnmatch.fnmatchcase(inp.tool, when.tool_glob)
    )


def _effect_ok(when: When, inp: GateInput, policy: Policy) -> bool:
    return (when.effect is None or inp.effect == when.effect) and (
        when.effect_in is None or inp.effect in when.effect_in
    )


def _who_ok(when: When, inp: GateInput, policy: Policy) -> bool:
    return (when.principal_in is None or inp.principal in when.principal_in) and (
        when.agent_in is None or inp.agent_id in when.agent_in
    )


def _resources_ok(when: When, inp: GateInput, policy: Policy) -> bool:
    tags = _tags(inp)
    ids = {r.id for r in inp.resources} | {i for r in inp.resources for i in r.ids}
    return (
        (when.resource_tags_any is None or bool(tags & set(when.resource_tags_any)))
        and (when.resource_tags_all is None or set(when.resource_tags_all) <= tags)
        and (when.resource_ids_any is None or bool(ids & set(when.resource_ids_any)))
        and (when.resource_count_gt is None or _count_over(when.resource_count_gt, inp))
    )


def _count_over(count: ResourceCount, inp: GateInput) -> bool:
    """Distinct resources of the kind, across every argument (to, cc and bcc together)."""
    return len({r.uri for r in inp.resources if r.kind == count.kind}) > count.value


def _taint_ok(when: When, inp: GateInput, policy: Policy) -> bool:
    t = when.run_taint
    if t is None:
        return True
    untrusted = t.untrusted_input is None or inp.taint.untrusted_input == t.untrusted_input
    private = t.private_data is None or inp.taint.private_data == t.private_data
    return untrusted and private


def _context_ok(when: When, inp: GateInput, policy: Policy) -> bool:
    window = when.time_window
    return (
        (window is None or _window_active(policy, window.cron_active, inp.now))
        and (when.outside_scope is None or inp.outside_scope == when.outside_scope)
        and (when.scope_required is None or when.scope_required not in inp.scopes)
        and (
            when.outbound_findings_any is None
            or bool(inp.outbound_findings & set(when.outbound_findings_any))
        )
    )


def _args_ok(when: When, inp: GateInput, policy: Policy) -> bool:
    return when.args is None or all(evaluate(c, inp.args) for c in when.args)


_CHECKS: Final = (_tool_ok, _effect_ok, _who_ok, _resources_ok, _taint_ok, _context_ok, _args_ok)


def _matches(when: When, inp: GateInput, policy: Policy) -> bool:
    """Every condition in ``when`` holds. Cheap checks run before argument checks."""
    return all(check(when, inp, policy) for check in _CHECKS)


def _evaluate_rule(
    rule: Rule, inp: GateInput, counters: Mapping[str, float]
) -> tuple[RuleMatch | None, BudgetCharge | None]:
    if rule.budget is None:
        assert rule.then is not None  # noqa: S101, guaranteed by the schema
        delay = rule.delay_seconds or 0.0
        return RuleMatch(
            rule.id, rule.then, rule.reason, rule.always_enforce, delay_seconds=delay
        ), None
    assert rule.then_exceeded is not None  # noqa: S101, guaranteed by the schema
    key = budget_key(rule.id, rule.budget, inp)
    amount = _measure(rule.budget, inp.args)
    exceeded = amount is None or counters.get(key, 0.0) + amount > rule.budget.limit
    if exceeded:
        match = RuleMatch(
            rule.id, rule.then_exceeded, rule.reason, rule.always_enforce, budget=True
        )
        return match, None
    assert amount is not None  # noqa: S101, checked just above
    if amount == 0:
        return None, None  # nothing to reserve
    return None, BudgetCharge(rule.id, key, amount, rule.budget.limit)


def decide(inp: GateInput, policy: Policy, counters: Mapping[str, float]) -> Decision:
    """Decide one action. Pure: no I/O, no clock, no mutation of the inputs."""
    matches: list[RuleMatch] = []
    charges: list[BudgetCharge] = []
    for rule in policy.rules:
        if not _matches(rule.when, inp, policy):
            continue
        match, charge = _evaluate_rule(rule, inp, counters)
        if match is not None:
            matches.append(match)
        if charge is not None:
            charges.append(charge)

    if matches:
        winner = _strictest(matches)
    else:
        fallback = _default(policy, inp.effect)
        reason = f"No rule matched; the policy default for {inp.effect} is {fallback}."
        winner = RuleMatch("default", fallback, reason)

    # Outside the run's scope, on_outside_scope is a floor: it can make the
    # outcome stricter but never more lenient than the rules or the default.
    if inp.outside_scope:
        floor = RuleMatch("outside-scope", policy.on_outside_scope, OUTSIDE_SCOPE_REASON)
        matches.append(floor)
        if RANK[floor.outcome] > RANK[winner.outcome]:
            winner = floor

    # Enforce wins: a run cannot loosen an enforcing policy, and a policy in
    # shadow mode still enforces for a run that asks for it.
    mode: Literal["enforce", "shadow"] = (
        "shadow" if policy.mode == "shadow" and inp.mode != "enforce" else "enforce"
    )
    applied = winner if mode == "enforce" else _shadow_winner(matches)
    return Decision(
        outcome=applied.outcome,
        shadow_outcome=winner.outcome,
        rule_id=applied.rule_id,
        reason=applied.reason,
        mode=mode,
        matches=tuple(matches),
        charges=tuple(charges) if applied.outcome != "deny" else (),
        delay_seconds=applied.delay_seconds if applied.outcome == "delay" else 0.0,
        shadow_rule_id=winner.rule_id,
        shadow_reason=winner.reason,
    )


def _strictest(matches: list[RuleMatch]) -> RuleMatch:
    """The strictest match: the first among equals, or the longest among delays."""
    best = max(RANK[m.outcome] for m in matches)
    tied = [m for m in matches if RANK[m.outcome] == best]
    return max(tied, key=lambda m: m.delay_seconds)  # max keeps the first of equal keys


SHADOW_REASON: Final = "Shadow mode: the decision is recorded but not enforced."


def _shadow_winner(matches: list[RuleMatch]) -> RuleMatch:
    """In shadow mode only always_enforce rules apply; name the one that did."""
    hard = [m for m in matches if m.always_enforce]
    if not hard:
        return RuleMatch("shadow-mode", "allow", SHADOW_REASON)
    return _strictest(hard)


def _default(policy: Policy, effect: Effect) -> Outcome:
    defaults = policy.default
    table: dict[str, Outcome] = {
        "read": defaults.read,
        "write": defaults.write,
        "destructive": defaults.destructive,
        "external_comm": defaults.external_comm,
        "financial": defaults.financial,
    }
    return table[effect]
