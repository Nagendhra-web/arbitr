"""The delay outcome: a cancel window before an allowed action runs."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from arbitr.core.errors import PolicyError
from arbitr.policy.engine import GateInput, decide
from arbitr.policy.schema import load_policy
from arbitr.policy.testing import load_cases

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)

POLICY = load_policy("""
version: 1
rules:
  - id: hold-bulk-email
    when: {tool: email.send_bulk}
    then: delay 60s
    reason: Bulk email waits a minute so someone can cancel it.
  - id: hold-bulk-email-longer
    when: {tool: email.send_bulk, args: [{path: $.count, op: gt, value: 1000}]}
    then: delay 5m
    reason: Very large sends wait five minutes.
  - id: no-bulk-to-all
    when: {tool: email.send_bulk, args: [{path: $.list, op: eq, value: everyone}]}
    then: deny
    reason: Never email every customer at once.
  - id: review-press
    when: {tool: email.send_bulk, args: [{path: $.list, op: eq, value: press}]}
    then: require_approval
    reason: Press emails need a human.
""")


def gate(args: dict[str, object], mode: str | None = None) -> GateInput:
    return GateInput(
        tool="email.send_bulk",
        effect="external_comm",
        args=args,
        principal="alice",
        agent_id="bot",
        run_id="r1",
        now=NOW,
        mode=mode,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("delay 60s", 60.0), ("delay 5m", 300.0), ("delay 2h", 7200.0), ("delay 90", 90.0)],
)
def test_delay_durations_parse(text: str, seconds: float) -> None:
    policy = load_policy(
        f"version: 1\nrules:\n  - id: r\n    when: {{tool: t.x}}\n    then: {text}\n    reason: x\n"
    )
    rule = policy.rules[0]
    assert rule.then == "delay"
    assert rule.delay_seconds == seconds


@pytest.mark.parametrize(
    "then",
    ["delay", "delay 0s", "delay -5s", "delay 25h", "delay soon", "delay 1e9", "wait 5s"],
)
def test_bad_delays_are_rejected(then: str) -> None:
    text = (
        f"version: 1\nrules:\n  - id: r\n    when: {{tool: t.x}}\n    then: {then}\n    reason: x\n"
    )
    with pytest.raises(PolicyError):
        load_policy(text)


def test_a_budget_cannot_delay_when_exceeded() -> None:
    with pytest.raises(PolicyError):
        load_policy("""
version: 1
rules:
  - id: r
    when: {tool: t.x}
    budget: {scope: [run], count: true, limit: 2}
    then_exceeded: delay 60s
    reason: x
""")


def test_delay_seconds_without_a_delay_is_rejected() -> None:
    with pytest.raises(PolicyError):
        load_policy(
            "version: 1\nrules:\n  - id: r\n    when: {tool: t.x}\n    then: allow\n"
            "    delay_seconds: 30\n    reason: x\n"
        )


def test_a_delay_rule_schedules_the_action() -> None:
    decision = decide(gate({"list": "newsletter", "count": 10}), POLICY, {})
    assert (decision.outcome, decision.rule_id, decision.delay_seconds) == (
        "delay",
        "hold-bulk-email",
        60.0,
    )


def test_the_longest_matching_delay_wins() -> None:
    decision = decide(gate({"list": "newsletter", "count": 5000}), POLICY, {})
    assert (decision.rule_id, decision.delay_seconds) == ("hold-bulk-email-longer", 300.0)


@pytest.mark.parametrize(
    ("args", "outcome"),
    [({"list": "everyone"}, "deny"), ({"list": "press"}, "require_approval")],
)
def test_deny_and_approval_beat_delay(args: dict[str, object], outcome: str) -> None:
    decision = decide(gate(args), POLICY, {})
    assert decision.outcome == outcome
    assert decision.delay_seconds == 0.0


def test_delay_beats_allow() -> None:
    policy = load_policy("""
version: 1
rules:
  - id: ok
    when: {tool: email.send_bulk}
    then: allow
    reason: Fine.
  - id: hold
    when: {tool: email.send_bulk}
    then: delay 30s
    reason: Wait.
""")
    assert decide(gate({}), policy, {}).outcome == "delay"


def test_shadow_mode_does_not_delay() -> None:
    policy = POLICY.model_copy(update={"mode": "shadow"})
    decision = decide(gate({"list": "newsletter"}), policy, {})
    assert decision.outcome == "allow"
    assert decision.shadow_outcome == "delay"
    assert decision.delay_seconds == 0.0


def test_case_files_can_expect_a_delay() -> None:
    (case,) = load_cases("""
cases:
  - name: bulk email waits
    tool: email.send_bulk
    effect: external_comm
    args: {list: newsletter}
    expect: delay
""")
    assert case.expect == "delay"
