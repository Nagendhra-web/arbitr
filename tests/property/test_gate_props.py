"""Properties of the gate that must hold for every policy."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from arbitr.policy.engine import RANK, GateInput, decide
from arbitr.policy.schema import Policy, Rule, When

OUTCOMES = ["allow", "deny", "require_approval"]

rule_specs = st.lists(
    st.tuples(st.sampled_from(OUTCOMES), st.booleans(), st.booleans()),
    min_size=1,
    max_size=8,
)


def build(specs: list[tuple[str, bool, bool]], mode: str) -> Policy:
    """Each rule either matches tool 't' or tool 'other', with an outcome."""
    rules = tuple(
        Rule(
            id=f"r{i}",
            when=When(tool="t" if hits else "other"),
            then=outcome,  # type: ignore[arg-type]
            reason=f"reason {i}",
            always_enforce=hard,
        )
        for i, (outcome, hits, hard) in enumerate(specs)
    )
    return Policy(version=1, mode=mode, rules=rules)  # type: ignore[arg-type]


INPUT = GateInput(
    tool="t",
    effect="write",
    args={},
    principal="p",
    agent_id="a",
    run_id="r",
    now=datetime(2026, 1, 1, tzinfo=UTC),
)


@given(rule_specs)
def test_strictest_matching_outcome_wins(specs: list[tuple[str, bool, bool]]) -> None:
    decision = decide(INPUT, build(specs, "enforce"), {})
    matching = [o for o, hits, _ in specs if hits]
    if not matching:
        assert decision.rule_id == "default"
        return
    strictest = max(matching, key=RANK.__getitem__)
    assert decision.outcome == strictest
    # The reported rule is the first matching rule with that outcome.
    first = next(i for i, (o, hits, _) in enumerate(specs) if hits and o == strictest)
    assert decision.rule_id == f"r{first}"


@given(rule_specs)
def test_deny_always_beats_allow(specs: list[tuple[str, bool, bool]]) -> None:
    decision = decide(INPUT, build(specs, "enforce"), {})
    if any(o == "deny" and hits for o, hits, _ in specs):
        assert decision.outcome == "deny"


@given(rule_specs)
def test_shadow_mode_never_blocks_unless_always_enforced(
    specs: list[tuple[str, bool, bool]],
) -> None:
    decision = decide(INPUT, build(specs, "shadow"), {})
    hard = [o for o, hits, always in specs if hits and always]
    if not hard:
        assert decision.outcome == "allow"
    else:
        assert decision.outcome == max(hard, key=RANK.__getitem__)
    # What enforce mode would have done is always recorded.
    assert decision.shadow_outcome == decide(INPUT, build(specs, "enforce"), {}).outcome


@given(rule_specs)
def test_reason_comes_from_the_policy(specs: list[tuple[str, bool, bool]]) -> None:
    decision = decide(INPUT, build(specs, "enforce"), {})
    assert decision.reason.startswith(("reason ", "No rule matched"))


@given(
    rule_specs,
    st.sampled_from(OUTCOMES),
    st.sampled_from(["read", "write", "destructive", "external_comm", "financial"]),
)
def test_being_outside_scope_never_loosens_the_outcome(
    specs: list[tuple[str, bool, bool]], floor: str, effect: str
) -> None:
    policy = build(specs, "enforce").model_copy(update={"on_outside_scope": floor})
    inside = decide(replace(INPUT, effect=effect), policy, {})
    outside = decide(replace(INPUT, effect=effect, outside_scope=True), policy, {})
    assert RANK[outside.outcome] == max(RANK[inside.outcome], RANK[floor])
