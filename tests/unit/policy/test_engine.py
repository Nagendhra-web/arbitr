"""The deterministic gate: matching, precedence, defaults, budgets, shadow mode."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from arbitr.core.errors import PolicyError
from arbitr.policy.engine import (
    GateInput,
    ResolvedResource,
    Taint,
    budget_key,
    decide,
)
from arbitr.policy.ops import evaluate
from arbitr.policy.schema import ArgCondition, load_policy

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
FREEZE = datetime(2026, 12, 25, 12, 0, tzinfo=UTC)

POLICY = load_policy("""
version: 1
resources:
  - id: prod-db
    match: {kind: database, uri_glob: "postgres://*prod*"}
    tags: [production, critical]
rules:
  - id: no-destroy-critical
    when: {effect: destructive, resource_tags_any: [critical]}
    then: deny
    reason: Destructive actions on critical resources are never allowed for agents.
    always_enforce: true
  - id: code-freeze
    when:
      effect_in: [write, destructive]
      resource_tags_any: [production]
      time_window: {cron_active: freeze}
    then: deny
    reason: Production is in a code freeze.
  - id: big-refunds
    when: {tool: payments.refund, args: [{path: $.amount, op: gt, value: 100}]}
    then: require_approval
    reason: Refunds over 100 need a human.
  - id: refund-daily-cap
    when: {tool: payments.refund}
    budget: {scope: [principal, day], sum_path: $.amount, limit: 500}
    then_exceeded: deny
    reason: Daily refund cap reached.
  - id: lethal-trifecta
    when: {effect: external_comm, run_taint: {untrusted_input: true, private_data: true}}
    then: require_approval
    reason: Run read untrusted input and private data, outbound message needs a human.
  - id: mass-email
    when: {tool: email.send}
    budget: {scope: [run], count: true, limit: 20}
    then_exceeded: deny
    reason: Too many emails in one run.
  - id: staging-ok
    when: {tool_glob: "deploy.*", args: [{path: $.env, op: eq, value: staging}]}
    then: allow
    reason: Staging deploys are fine.
windows:
  freeze: {start: "2026-12-20T00:00:00Z", end: "2027-01-05T00:00:00Z"}
""")

PROD = ResolvedResource(
    id="prod-db",
    kind="database",
    uri="postgres://prod/orders",
    tags=frozenset({"production", "critical"}),
)


def gate(tool: str, effect: str, args: dict[str, object] | None = None, **kw: object) -> GateInput:
    base = GateInput(
        tool=tool,
        effect=effect,
        args=args or {},
        principal="alice",  # type: ignore[arg-type]
        agent_id="bot",
        run_id="r1",
        now=NOW,
    )
    return replace(base, **kw)  # type: ignore[arg-type]


# ---------------------------------------------------------------- precedence and defaults


def test_no_rule_uses_the_default_for_the_effect() -> None:
    d = decide(gate("db.query", "read"), POLICY, {})
    assert (d.outcome, d.rule_id) == ("allow", "default")
    d = decide(gate("rm", "destructive"), POLICY, {})
    assert (d.outcome, d.rule_id) == ("require_approval", "default")
    assert "default for destructive" in d.reason


def test_deny_beats_require_approval_beats_allow() -> None:
    d = decide(gate("db.exec", "destructive", resources=(PROD,), now=FREEZE), POLICY, {})
    assert d.outcome == "deny"
    assert d.rule_id == "no-destroy-critical"  # first deny in file order
    assert {m.rule_id for m in d.matches} >= {"no-destroy-critical", "code-freeze"}


def test_require_approval_with_a_reason_from_the_policy() -> None:
    d = decide(gate("payments.refund", "financial", {"amount": 150}), POLICY, {})
    assert (d.outcome, d.rule_id) == ("require_approval", "big-refunds")
    assert d.reason == "Refunds over 100 need a human."


def test_matching_allow_rule_overrides_the_default() -> None:
    d = decide(gate("deploy.app", "destructive", {"env": "staging"}), POLICY, {})
    assert (d.outcome, d.rule_id) == ("allow", "staging-ok")


def test_reason_never_contains_argument_values() -> None:
    secretish = "do-not-echo-this-value"
    d = decide(gate("payments.refund", "financial", {"amount": 150, "memo": secretish}), POLICY, {})
    assert secretish not in d.reason
    assert secretish not in d.explain()


# ---------------------------------------------------------------- windows and taint


def test_time_window_only_applies_while_active() -> None:
    before = decide(gate("db.write", "write", resources=(PROD,)), POLICY, {})
    during = decide(gate("db.write", "write", resources=(PROD,), now=FREEZE), POLICY, {})
    after = decide(
        gate("db.write", "write", resources=(PROD,), now=datetime(2027, 1, 5, tzinfo=UTC)),
        POLICY,
        {},
    )
    assert (before.outcome, during.outcome, after.outcome) == ("allow", "deny", "allow")


def test_lethal_trifecta_needs_both_taint_flags() -> None:
    both = Taint(untrusted_input=True, private_data=True)
    one = Taint(untrusted_input=True)
    assert decide(gate("slack.post", "external_comm", taint=both), POLICY, {}).outcome == (
        "require_approval"
    )
    assert decide(gate("slack.post", "external_comm", taint=one), POLICY, {}).outcome == "allow"


# ---------------------------------------------------------------- budgets


def test_budget_charges_within_the_limit() -> None:
    d = decide(gate("payments.refund", "financial", {"amount": 40}), POLICY, {})
    assert d.outcome == "require_approval"  # financial default
    charge = next(c for c in d.charges if c.rule_id == "refund-daily-cap")
    assert charge.amount == 40
    assert charge.limit == 500
    assert charge.scope_key == "rule:refund-daily-cap|principal:alice|day:2026-10-25"


def test_budget_fires_when_the_charge_would_exceed() -> None:
    key = "rule:refund-daily-cap|principal:alice|day:2026-10-25"
    d = decide(gate("payments.refund", "financial", {"amount": 60}), POLICY, {key: 450})
    assert (d.outcome, d.rule_id) == ("deny", "refund-daily-cap")
    assert d.reason == "Daily refund cap reached."
    assert not any(c.rule_id == "refund-daily-cap" for c in d.charges)


def test_budget_at_exactly_the_limit_is_allowed() -> None:
    key = "rule:refund-daily-cap|principal:alice|day:2026-10-25"
    d = decide(gate("payments.refund", "financial", {"amount": 50}), POLICY, {key: 450})
    assert d.rule_id != "refund-daily-cap"


def test_count_budget() -> None:
    key = "rule:mass-email|run:r1"
    assert decide(gate("email.send", "external_comm"), POLICY, {key: 19}).outcome == "allow"
    d = decide(gate("email.send", "external_comm"), POLICY, {key: 20})
    assert (d.outcome, d.rule_id) == ("deny", "mass-email")


@pytest.mark.parametrize("amount", [None, "a lot", True, [1, 2]])
def test_unmeasurable_budget_amount_fails_safe(amount: object) -> None:
    args = {} if amount is None else {"amount": amount}
    d = decide(gate("payments.refund", "financial", args), POLICY, {})
    assert (d.outcome, d.rule_id) == ("deny", "refund-daily-cap")


def test_budget_keys_cover_each_scope() -> None:
    policy = load_policy("""
version: 1
rules:
  - id: k
    when: {tool: t}
    budget: {scope: [principal, agent, run, tool, day, hour], count: true, limit: 1}
    then_exceeded: deny
    reason: r
""")
    budget = policy.rules[0].budget
    assert budget is not None
    key = budget_key("k", budget, gate("t", "write"))
    assert key == "rule:k|principal:alice|agent:bot|run:r1|tool:t|day:2026-10-25|hour:2026-10-25T12"


# ---------------------------------------------------------------- shadow mode


def test_shadow_mode_allows_but_records_what_enforce_would_do() -> None:
    shadow = POLICY.model_copy(update={"mode": "shadow"})
    d = decide(gate("payments.refund", "financial", {"amount": 150}), shadow, {})
    assert d.outcome == "allow"
    assert d.shadow_outcome == "require_approval"
    assert (d.rule_id, d.shadow_rule_id) == ("shadow-mode", "big-refunds")


def test_shadow_mode_still_enforces_always_enforce_rules() -> None:
    d = decide(gate("db.exec", "destructive", resources=(PROD,), mode="shadow"), POLICY, {})
    assert (d.outcome, d.shadow_outcome) == ("deny", "deny")


def test_always_enforce_applies_even_when_another_deny_wins() -> None:
    policy = load_policy("""
version: 1
mode: shadow
rules:
  - {id: plain-deny, when: {tool: t}, then: deny, reason: first}
  - id: hard-approval
    when: {tool: t}
    then: require_approval
    reason: second
    always_enforce: true
""")
    d = decide(gate("t", "write"), policy, {})
    assert d.shadow_outcome == "deny"
    assert d.outcome == "require_approval"


def test_policy_mode_shadow_applies_by_default() -> None:
    policy = load_policy("version: 1\nmode: shadow\n")
    d = decide(gate("rm", "destructive"), policy, {})
    assert (d.outcome, d.shadow_outcome) == ("allow", "require_approval")


def test_enforce_mode_outcome_equals_shadow_outcome() -> None:
    d = decide(gate("payments.refund", "financial", {"amount": 150}), POLICY, {})
    assert d.outcome == d.shadow_outcome


# ---------------------------------------------------------------- other match keys


@pytest.mark.parametrize(
    ("when", "inp", "matches"),
    [
        ("{principal_in: [alice]}", {}, True),
        ("{principal_in: [bob]}", {}, False),
        ("{agent_in: [bot]}", {}, True),
        ("{resource_ids_any: [prod-db]}", {"resources": (PROD,)}, True),
        ("{resource_tags_all: [production, critical]}", {"resources": (PROD,)}, True),
        ("{resource_tags_all: [production, public]}", {"resources": (PROD,)}, False),
        ("{outside_scope: true}", {"outside_scope": True}, True),
        ("{outside_scope: true}", {}, False),
        ("{scope_required: payments}", {"scopes": frozenset({"email"})}, True),
        ("{scope_required: payments}", {"scopes": frozenset({"payments"})}, False),
        ("{outbound_findings_any: [secret]}", {"outbound_findings": frozenset({"secret"})}, True),
        ("{outbound_findings_any: [secret]}", {"outbound_findings": frozenset({"email"})}, False),
        ("{tool_glob: 'db.*'}", {}, True),
        ("{tool_glob: 'fs.*'}", {}, False),
    ],
)
def test_match_keys(when: str, inp: dict[str, object], matches: bool) -> None:
    policy = load_policy(
        f"version: 1\nrules:\n  - {{id: k, when: {when}, then: deny, reason: r}}\n"
    )
    d = decide(replace(gate("db.query", "read"), **inp), policy, {})  # type: ignore[arg-type]
    assert (d.rule_id == "k") is matches


# ---------------------------------------------------------------- explain


def test_explain_lists_every_matching_rule_and_the_winner() -> None:
    d = decide(gate("db.exec", "destructive", resources=(PROD,), now=FREEZE), POLICY, {})
    text = d.explain()
    assert "deny by rule no-destroy-critical" in text
    assert "code-freeze" in text
    assert "deny beats require_approval beats delay beats allow" in text


def test_decide_is_pure() -> None:
    inp = gate("payments.refund", "financial", {"amount": 150})
    counters = {"x": 1.0}
    assert decide(inp, POLICY, counters) == decide(inp, POLICY, counters)
    assert counters == {"x": 1.0}


# ---------------------------------------------------------------- operators


def cond(path: str, op: str, value: object = None) -> ArgCondition:
    return ArgCondition(path=path, op=op, value=value)  # type: ignore[arg-type]


ARGS = {
    "n": 5,
    "f": 2.5,
    "s": "hello world",
    "b": True,
    "l": [1, "x", 3],
    "o": {"k": "v"},
    "items": [{"amt": 10}, {"amt": 200}],
    "z": None,
}


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (cond("$.n", "eq", 5), True),
        (cond("$.n", "eq", 5.0), True),
        (cond("$.b", "eq", 1), False),
        (cond("$.n", "eq", True), False),
        (cond("$.z", "eq", None), True),
        (cond("$.n", "ne", 6), True),
        (cond("$.n", "ne", 5), False),
        (cond("$.missing", "ne", 1), False),
        (cond("$.n", "in", [1, 5]), True),
        (cond("$.n", "in", ["5"]), False),
        (cond("$.n", "not_in", [1, 2]), True),
        (cond("$.n", "not_in", [5]), False),
        (cond("$.n", "gt", 4), True),
        (cond("$.n", "gt", 5), False),
        (cond("$.n", "gte", 5), True),
        (cond("$.f", "lt", 3), True),
        (cond("$.f", "lte", 2.5), True),
        (cond("$.s", "gt", 1), False),
        (cond("$.b", "gt", 0), False),
        (cond("$.s", "glob", "hello*"), True),
        (cond("$.s", "glob", "HELLO*"), False),
        (cond("$.n", "glob", "5"), False),
        (cond("$.s", "regex", "^hel+o\\s"), True),
        (cond("$.s", "regex", "^world"), False),
        (cond("$.s", "contains", "lo wo"), True),
        (cond("$.l", "contains", "x"), True),
        (cond("$.l", "contains", 2), False),
        (cond("$.o", "contains", "k"), True),
        (cond("$.n", "exists"), True),
        (cond("$.missing", "exists"), False),
        (cond("$.missing", "exists", False), True),
        (cond("$.n", "exists", False), False),
        (cond("$.s", "len_gt", 5), True),
        (cond("$.l", "len_gt", 3), False),
        (cond("$.n", "len_gt", 0), False),
        (cond("$.items[*].amt", "gt", 100), True),
        (cond("$.items[*].amt", "gt", 500), False),
        (cond("$.items[*].amt", "ne", 10), False),
        (cond("$.items[*].amt", "not_in", [1, 2]), True),
    ],
)
def test_operator(condition: ArgCondition, expected: bool) -> None:
    assert evaluate(condition, ARGS) is expected


def test_regex_input_is_bounded() -> None:
    big = {"s": "a" * 1_000_000 + "!"}
    assert evaluate(cond("$.s", "regex", "!$"), big) is False  # only the first part is searched


def test_resource_count_counts_distinct_resources_of_one_kind() -> None:
    policy = load_policy("""
version: 1
rules:
  - id: crowd
    when: { effect: external_comm, resource_count_gt: { kind: email, value: 2 } }
    then: require_approval
    reason: Too many recipients.
""")

    def mail(*uris: str) -> tuple[ResolvedResource, ...]:
        return tuple(ResolvedResource(id=None, kind="email", uri=u) for u in uris)

    other = ResolvedResource(id=None, kind="url", uri="https://example.com")
    two = gate("email.send", "external_comm", resources=(*mail("a@x.io", "b@x.io"), other))
    three = gate("email.send", "external_comm", resources=mail("a@x.io", "b@x.io", "c@x.io"))
    same = gate("email.send", "external_comm", resources=mail("a@x.io", "a@x.io", "b@x.io"))
    assert decide(two, policy, {}).outcome == "allow"
    assert decide(three, policy, {}).outcome == "require_approval"
    assert decide(same, policy, {}).outcome == "allow"


def test_resource_count_needs_a_kind_and_a_non_negative_value() -> None:
    for bad in ("{ kind: email, value: -1 }", "{ value: 3 }", "{ kind: '', value: 3 }"):
        with pytest.raises(PolicyError):
            load_policy(
                "version: 1\nrules:\n  - id: r\n    when: { resource_count_gt: " + bad + " }\n"
                "    then: deny\n    reason: x\n"
            )


@pytest.mark.parametrize(
    ("value", "op", "target", "expected"),
    [
        ("500", "gt", 100, True),  # a tool's validator turns "500" into 500
        (" 500 ", "gte", 500, True),
        ("1e3", "gt", 100, True),
        ("1_000", "gt", 999, True),
        ("-5", "lt", 0, True),
        ("99.5", "lte", 100, True),
        ("50", "gt", 100, False),
        ("abc", "gt", 1, False),
        ("nan", "gt", 1, False),
        ("inf", "gt", 1, False),
        ("", "gt", -1, False),
        (True, "gt", 0, False),
    ],
)
def test_numeric_comparisons_read_numeric_strings_as_numbers(
    value: object, op: str, target: float, expected: bool
) -> None:
    assert (
        evaluate(ArgCondition(path="$.amount", op=op, value=target), {"amount": value}) is expected
    )


def test_a_numeric_string_cannot_slip_past_an_approval_threshold() -> None:
    policy = load_policy("""
version: 1
default: { financial: allow }
rules:
  - id: big-refunds
    when: { tool: payments.refund, args: [{ path: "$.amount", op: gt, value: 100 }] }
    then: require_approval
    reason: Refunds over 100 need a human.
""")
    for amount in (500, "500", "5e2"):
        result = decide(gate("payments.refund", "financial", {"amount": amount}), policy, {})
        assert result.outcome == "require_approval", amount
