"""Rules on preview facts, and the fail-safe when a preview failed."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import PolicyError
from arbitr.policy.engine import GateInput, decide
from arbitr.policy.schema import load_policy
from arbitr.policy.testing import gate_input, load_cases, run_cases

if TYPE_CHECKING:
    from collections.abc import Mapping

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)

POLICY = load_policy(
    """
version: 1
rules:
  - id: big-delete
    when:
      tool: db.exec
      preview: [{ path: "$.rows_affected", op: gt, value: 1000 }]
    then: require_approval
    reason: Deleting more than 1000 rows needs a human.
  - id: huge-delete
    when:
      tool: db.exec
      preview: [{ path: "$.rows_affected", op: gt, value: 100000 }]
    then: deny
    reason: Never delete more than 100000 rows.
  - id: small-delete
    when:
      tool: db.exec
      preview: [{ path: "$.rows_affected", op: lte, value: 1000 }]
    then: allow
    reason: Small deletes are fine.
"""
)


def _inp(
    preview: Mapping[str, object] | None = None, *, ok: bool = True, tool: str = "db.exec"
) -> GateInput:
    return GateInput(
        tool=tool, effect="destructive", args={}, principal="p", agent_id="a", run_id="r",
        now=NOW, preview=preview or {}, preview_ok=ok,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("rows", "outcome", "rule"),
    [(10, "allow", "small-delete"), (5000, "require_approval", "big-delete"),
     (500_000, "deny", "huge-delete")],
)  # fmt: skip
def test_rules_test_preview_facts(rows: int, outcome: str, rule: str) -> None:
    decision = decide(_inp({"rows_affected": rows}), POLICY, {})
    assert (decision.outcome, decision.rule_id) == (outcome, rule)
    assert not decision.preview_assumed


def test_without_a_preview_the_rules_do_not_match() -> None:
    decision = decide(_inp(), POLICY, {})
    assert decision.rule_id == "default"
    assert decision.outcome == "require_approval"


def test_a_failed_preview_takes_the_strictest_outcome() -> None:
    decision = decide(_inp({"rows_affected": 10}, ok=False), POLICY, {})
    assert decision.outcome == "deny"
    assert decision.rule_id == "huge-delete"
    assert decision.preview_assumed
    assert "preview failed" in decision.explain()


def test_a_failed_preview_never_turns_a_default_into_a_looser_rule() -> None:
    policy = load_policy(
        """
version: 1
rules:
  - id: small-delete
    when: { tool: db.exec, preview: [{ path: "$.rows_affected", op: lte, value: 10 }] }
    then: allow
    reason: Small deletes are fine.
  - id: medium-delete
    when: { tool: db.exec, preview: [{ path: "$.rows_affected", op: lte, value: 100 }] }
    then: delay 60s
    reason: Medium deletes wait a minute.
"""
    )
    passed = decide(_inp({"rows_affected": 5}), policy, {})
    assert passed.outcome == "delay"  # delay beats allow among matches
    failed = decide(_inp({"rows_affected": 5}, ok=False), policy, {})
    assert failed.outcome == "require_approval"  # the destructive default, not the delay
    assert failed.rule_id == "default"
    assert failed.preview_assumed


def test_a_failed_preview_still_applies_rules_without_preview_conditions() -> None:
    policy = load_policy(
        """
version: 1
rules:
  - id: no-prod
    when: { tool: db.exec }
    then: deny
    reason: No.
  - id: tiny
    when: { tool: db.exec, preview: [{ path: "$.rows_affected", op: lt, value: 2 }] }
    then: allow
    reason: Tiny.
"""
    )
    decision = decide(_inp(ok=False), policy, {})
    assert (decision.outcome, decision.rule_id) == ("deny", "no-prod")


def test_a_failed_preview_without_preview_rules_changes_nothing() -> None:
    policy = load_policy("version: 1\nrules:\n  - {id: r, when: {tool: db.exec}, then: allow,"
                         " reason: ok}\n")  # fmt: skip
    decision = decide(_inp(ok=False), policy, {})
    assert decision.outcome == "allow"
    assert not decision.preview_assumed


def test_other_conditions_still_have_to_hold_under_the_fail_safe() -> None:
    decision = decide(_inp(ok=False, tool="other.tool"), POLICY, {})
    assert decision.rule_id == "default"
    assert not decision.preview_assumed


def test_fail_safe_applies_to_budgets_too() -> None:
    policy = load_policy(
        """
version: 1
rules:
  - id: row-budget
    when: { tool: db.exec, preview: [{ path: "$.rows_affected", op: exists }] }
    budget: { scope: [run], count: true, limit: 1 }
    then_exceeded: deny
    reason: One big delete per run.
  - id: allow-db
    when: { tool: db.exec }
    then: allow
    reason: ok
"""
    )
    decision = decide(_inp(ok=False), policy, {"rule:row-budget|run:r": 1.0})
    assert decision.outcome == "deny"
    fresh = decide(_inp(ok=False), policy, {})
    assert fresh.outcome == "allow"
    assert [c.rule_id for c in fresh.charges] == ["row-budget"]


def test_shadow_mode_keeps_the_fail_safe_for_always_enforced_rules() -> None:
    policy = load_policy(
        """
version: 1
mode: shadow
rules:
  - id: huge
    when: { tool: db.exec, preview: [{ path: "$.rows_affected", op: gt, value: 100 }] }
    then: deny
    always_enforce: true
    reason: Never.
"""
    )
    assert decide(_inp({"rows_affected": 1}), policy, {}).outcome == "allow"
    failed = decide(_inp({"rows_affected": 1}, ok=False), policy, {})
    assert failed.outcome == "deny"
    assert failed.shadow_outcome == "deny"


def test_preview_conditions_are_validated() -> None:
    with pytest.raises(PolicyError, match="needs a number"):
        load_policy(
            "version: 1\nrules:\n  - id: r\n    when: {preview: [{path: $.rows, op: gt,"
            " value: x}]}\n    then: deny\n    reason: r\n"
        )
    only = load_policy(
        "version: 1\nrules:\n  - id: r\n    when: {preview: [{path: $.rows, op: exists}]}\n"
        "    then: deny\n    reason: r\n"
    )
    assert only.rules[0].when.preview is not None


def test_policy_cases_can_give_preview_facts() -> None:
    cases = load_cases(
        """
cases:
  - name: big
    tool: db.exec
    effect: destructive
    preview: { rows_affected: 5000 }
    expect: require_approval
    expect_rule: big-delete
  - name: failed preview
    tool: db.exec
    effect: destructive
    preview: { rows_affected: 5 }
    preview_ok: false
    expect: deny
"""
    )
    assert gate_input(cases[0], POLICY).preview == {"rows_affected": 5000}
    report = run_cases(POLICY, cases)
    assert report.ok, report.describe()
