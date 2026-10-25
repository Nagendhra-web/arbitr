"""Regex rules run on a linear-time engine, so no input can stall the gate."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from arbitr.core.errors import PolicyError
from arbitr.policy.engine import GateInput, decide
from arbitr.policy.ops import evaluate
from arbitr.policy.packs import PACKS
from arbitr.policy.schema import ArgCondition, load_policy

ADVERSARIAL = [
    " " * 10_000,
    "a" * 10_000,
    "a-" * 5_000,
    "gh " * 3_000 + "api",
    "kubectl " + "x" * 9_000,
    "terraform " * 1_000,
]


def pack_regexes() -> list[str]:
    policy = load_policy(f"version: 1\ninclude: [{', '.join(PACKS)}]\n")
    return sorted(
        {
            str(cond.value)
            for rule in policy.rules
            for cond in rule.when.args or ()
            if cond.op == "regex"
        }
    )


SLOW_ON_BACKTRACKING = [r"\s*\s*\s*x", r".*a.*b.*c", r"a*a*a*a*b", r"(a+)+$", r"(a|aa)*c"]


@pytest.mark.parametrize("pattern", SLOW_ON_BACKTRACKING + pack_regexes())
def test_every_regex_rule_finishes_quickly_on_adversarial_input(pattern: str) -> None:
    load_policy(
        "version: 1\nrules:\n  - id: r\n    when:\n      args:\n"
        f"        - {{ path: '$.s', op: regex, value: '{pattern}' }}\n"
        "    then: deny\n    reason: r\n"
    )
    cond = ArgCondition(path="$.s", op="regex", value=pattern)
    for text in ADVERSARIAL:
        started = time.perf_counter()
        evaluate(cond, {"s": text})
        assert time.perf_counter() - started < 0.05, (pattern, text[:20])


@pytest.mark.parametrize("pattern", [r"(?=x)a", r"(?!x)a", r"(?<=x)a", r"(a)\1", r"a\Z"])
def test_features_the_linear_engine_lacks_are_refused(pattern: str) -> None:
    with pytest.raises(PolicyError, match="regex"):
        load_policy(
            "version: 1\nrules:\n  - id: r\n    when:\n      args:\n"
            f"        - {{ path: '$.s', op: regex, value: '{pattern}' }}\n"
            "    then: deny\n    reason: r\n"
        )


def test_matching_semantics_are_unchanged() -> None:
    cond = ArgCondition(path="$.s", op="regex", value=r"(?i)^drop\s+table\b")
    assert evaluate(cond, {"s": "DROP TABLE users"})
    assert not evaluate(cond, {"s": "select 1"})
    end = ArgCondition(path="$.s", op="regex", value=r"x\z")
    assert evaluate(end, {"s": "abx"})


def test_a_decision_with_every_pack_is_fast_on_adversarial_input() -> None:
    policy = load_policy(f"version: 1\ninclude: [{', '.join(PACKS)}]\n")
    for text in ADVERSARIAL:
        inp = GateInput(
            tool="shell.run",
            effect="destructive",
            args={"command": text},
            principal="p",
            agent_id="a",
            run_id="r",
            now=datetime(2026, 10, 25, tzinfo=UTC),
        )
        started = time.perf_counter()
        decide(inp, policy, {})
        assert time.perf_counter() - started < 0.05


def test_a_trailing_newline_does_not_slip_past_a_dollar_anchor() -> None:
    cond = ArgCondition(path="$.s", op="regex", value=r"^rm -rf /$")
    assert evaluate(cond, {"s": "rm -rf /\n"})
    assert evaluate(cond, {"s": "rm -rf /"})
    assert not evaluate(cond, {"s": "rm -rf /\n\n"})  # Python's $ does not match here either


@pytest.mark.parametrize("space", ["\u00a0", "\u2028", "\u3000", "\v", "\x1c"])
def test_unicode_spaces_count_as_whitespace(space: str) -> None:
    cond = ArgCondition(path="$.s", op="regex", value=r"(?i)drop\s+table")
    assert evaluate(cond, {"s": f"DROP{space}TABLE users"})


def test_lone_surrogates_do_not_break_matching() -> None:
    cond = ArgCondition(path="$.s", op="regex", value=r"rm -rf")
    assert evaluate(cond, {"s": "rm -rf \ud800"})
    inp = GateInput(
        tool="shell.run",
        effect="write",
        args={"command": "echo \ud800"},
        principal="p",
        agent_id="a",
        run_id="r",
        now=datetime(2026, 10, 25, tzinfo=UTC),
    )
    policy = load_policy(f"version: 1\ninclude: [{', '.join(PACKS)}]\n")
    assert decide(inp, policy, {}).outcome in ("allow", "deny", "require_approval")
