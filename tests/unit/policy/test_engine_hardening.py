"""Gate edge cases: run modes, shadow attribution, time, effects and budget keys."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from arbitr.policy.engine import GateInput, budget_key, decide
from arbitr.policy.schema import load_policy

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)


def gate(**kw: object) -> GateInput:
    base = GateInput(
        tool="fs.write",
        effect="write",
        args={},
        principal="p",
        agent_id="a",
        run_id="r",
        now=NOW,
    )
    return replace(base, **kw)  # type: ignore[arg-type]


DENY_WRITES = load_policy(
    "version: 1\nrules:\n  - id: no-writes\n    when: { tool: fs.write }\n    then: deny\n"
    "    reason: No writes.\n"
)


# ---------------------------------------------------------------- mode


def test_a_shadow_run_cannot_loosen_an_enforce_policy() -> None:
    d = decide(gate(mode="shadow"), DENY_WRITES, {})
    assert (d.outcome, d.mode) == ("deny", "enforce")


def test_an_enforce_run_tightens_a_shadow_policy() -> None:
    policy = DENY_WRITES.model_copy(update={"mode": "shadow"})
    assert decide(gate(mode="enforce"), policy, {}).outcome == "deny"
    assert decide(gate(), policy, {}).outcome == "allow"


# ---------------------------------------------------------------- shadow attribution

SHADOW = load_policy(
    "version: 1\nmode: shadow\nrules:\n"
    "  - id: plain-deny\n    when: { tool: fs.write }\n    then: deny\n    reason: plain\n"
    "  - id: hard-approval\n    when: { tool: fs.write }\n    then: require_approval\n"
    "    always_enforce: true\n    reason: hard\n"
)


def test_shadow_mode_names_the_rule_behind_the_applied_outcome() -> None:
    d = decide(gate(), SHADOW, {})
    assert (d.outcome, d.rule_id, d.reason) == ("require_approval", "hard-approval", "hard")
    assert (d.shadow_outcome, d.shadow_rule_id, d.shadow_reason) == ("deny", "plain-deny", "plain")


def test_shadow_mode_without_hard_rules_says_so() -> None:
    policy = DENY_WRITES.model_copy(update={"mode": "shadow"})
    d = decide(gate(), policy, {})
    assert (d.outcome, d.rule_id) == ("allow", "shadow-mode")
    assert (d.shadow_outcome, d.shadow_rule_id) == ("deny", "no-writes")


def test_enforce_mode_shadow_fields_repeat_the_decision() -> None:
    d = decide(gate(), DENY_WRITES, {})
    assert (d.shadow_rule_id, d.shadow_reason) == (d.rule_id, d.reason)


# ---------------------------------------------------------------- budgets

CAP = load_policy(
    "version: 1\nrules:\n  - id: cap\n    when: { tool: pay }\n"
    "    budget: { scope: [principal, day], sum_path: '$.amount', limit: 100 }\n"
    "    then_exceeded: deny\n    reason: Cap.\n"
)


def test_a_zero_amount_reserves_nothing() -> None:
    d = decide(gate(tool="pay", args={"amount": 0}), CAP, {})
    assert d.outcome == "allow"
    assert d.charges == ()


def test_budget_days_are_utc_days() -> None:
    plus_530 = timezone(timedelta(hours=5, minutes=30))
    late_utc = datetime(2026, 1, 5, 23, 30, tzinfo=UTC)
    same_instant = late_utc.astimezone(plus_530)
    keys = {
        budget_key("cap", CAP.rules[0].budget, gate(tool="pay", now=t))  # type: ignore[arg-type]
        for t in (late_utc, same_instant)
    }
    assert keys == {"rule:cap|principal:p|day:2026-01-05"}


def test_budget_key_values_cannot_collide() -> None:
    budget = (
        load_policy(
            "version: 1\nrules:\n  - id: c\n    when: { tool: pay }\n"
            "    budget: { scope: [principal, run], count: true, limit: 1 }\n"
            "    then_exceeded: deny\n    reason: c\n"
        )
        .rules[0]
        .budget
    )
    a = budget_key("c", budget, gate(principal="a|run:b", run_id="c"))  # type: ignore[arg-type]
    b = budget_key("c", budget, gate(principal="a", run_id="b|run:c"))  # type: ignore[arg-type]
    assert a != b


# ---------------------------------------------------------------- input validation


def test_a_naive_time_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone"):
        gate(now=datetime(2026, 10, 25, 12, 0))  # noqa: DTZ001 - the point of the test


def test_times_are_stored_in_utc() -> None:
    plus_530 = timezone(timedelta(hours=5, minutes=30))
    assert gate(now=NOW.astimezone(plus_530)).now.tzinfo == UTC


@pytest.mark.parametrize("effect", ["bogus", "model_config", ""])
def test_an_unknown_effect_is_refused(effect: str) -> None:
    with pytest.raises(ValueError, match="effect"):
        gate(effect=effect)
