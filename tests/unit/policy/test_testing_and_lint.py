"""`policy test` case tables, `policy lint`, and the explain text."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arbitr.cli import main as cli_main
from arbitr.core.errors import PolicyError
from arbitr.core.spec import ToolSpec
from arbitr.policy.lint import lint_policy
from arbitr.policy.schema import load_policy
from arbitr.policy.testing import load_cases, run_cases

POLICY_YAML = """
version: 1
resources:
  - id: prod-db
    match: { kind: database, uri_glob: "postgres://*prod*" }
    tags: [production]
  - id: backups
    match: { kind: path, glob: "/var/backups/**" }
    tags: [critical]
rules:
  - id: no-destroy-critical
    when: { effect: destructive, resource_tags_any: [critical] }
    then: deny
    reason: Destroying critical resources is not allowed.
  - id: prod-writes-need-approval
    when: { resource_tags_any: [production], effect_in: [write, destructive] }
    then: require_approval
    reason: Writes to production need a human.
  - id: no-secrets-out
    when: { effect: external_comm, outbound_findings_any: [secret] }
    then: deny
    reason: Outbound messages must not contain secrets.
  - id: big-refunds
    when:
      tool: payments.refund
      args: [{ path: "$.amount", op: gt, value: 100 }]
    then: require_approval
    reason: Refunds over 100 need a human.
"""

CASES_YAML = """
cases:
  - name: rm on backups is denied
    tool: shell.run
    args: { command: "rm -rf /var/backups/db" }
    expect: deny
    expect_rule: no-destroy-critical
  - name: prod write needs approval
    tool: db.exec
    args: { dsn: "postgres://app@db.prod/orders", sql: "UPDATE t SET a = 1 WHERE id = 2" }
    expect: require_approval
  - name: small refund is allowed
    tool: payments.refund
    effect: financial
    args: { amount: 20 }
    expect: require_approval
    expect_rule: default
  - name: secret in email is denied
    tool: email.send
    effect: external_comm
    args: { to: "x@example.com", body: "key AKIA%s" }
    expect: deny
  - name: reading is fine
    tool: fs.read
    effect: read
    args: { path: "/var/backups/db" }
    expect: allow
"""


@pytest.fixture
def files(tmp_path: Path) -> tuple[Path, Path]:
    policy = tmp_path / "policy.yaml"
    cases = tmp_path / "cases.yaml"
    policy.write_text(POLICY_YAML, encoding="utf-8")
    cases.write_text(CASES_YAML % ("QWERTYUIOPASDFGH",), encoding="utf-8")
    return policy, cases


# ---------------------------------------------------------------- case tables


def test_cases_run_against_the_policy(files: tuple[Path, Path]) -> None:
    policy, cases = files
    report = run_cases(load_policy(policy), load_cases(cases))
    assert report.ok, report.describe()
    assert report.passed == 5
    assert "5 passed, 0 failed" in report.describe()


def test_a_wrong_expectation_fails_with_an_explanation(files: tuple[Path, Path]) -> None:
    policy, _ = files
    cases = load_cases(
        "cases:\n  - name: wrong\n    tool: shell.run\n"
        "    args: { command: 'rm -rf /var/backups' }\n    expect: allow\n"
    )
    report = run_cases(load_policy(policy), cases)
    assert not report.ok
    text = report.describe()
    assert "FAIL wrong: expected allow, got deny by rule no-destroy-critical" in text
    assert "Matching rules" in text


def test_expect_rule_is_checked(files: tuple[Path, Path]) -> None:
    policy, _ = files
    cases = load_cases(
        "cases:\n  - name: r\n    tool: fs.read\n    effect: read\n    args: {}\n"
        "    expect: allow\n    expect_rule: something-else\n"
    )
    assert not run_cases(load_policy(policy), cases).ok


def test_case_files_are_validated() -> None:
    with pytest.raises(PolicyError, match="expect"):
        load_cases("cases:\n  - name: x\n    tool: t\n    expect: maybe\n")
    with pytest.raises(PolicyError, match="duplicate key"):
        load_cases("cases:\n  - name: x\n    name: y\n    tool: t\n    expect: allow\n")
    with pytest.raises(PolicyError, match="duplicate case name"):
        load_cases(
            "cases:\n  - {name: x, tool: t, expect: allow}\n  - {name: x, tool: t, expect: deny}\n"
        )


def test_cases_can_set_taint_scope_time_counters_and_mode() -> None:
    policy = load_policy(
        "version: 1\nrules:\n"
        "  - id: trifecta\n"
        "    when:\n      effect: external_comm\n"
        "      run_taint: { untrusted_input: true, private_data: true }\n"
        "    then: deny\n    reason: Trifecta.\n"
        "  - id: cap\n    when: { tool: pay }\n"
        "    budget: { scope: [run], sum_path: '$.amount', limit: 100 }\n"
        "    then_exceeded: deny\n    reason: Cap.\n"
    )
    cases = load_cases(
        """
cases:
  - name: trifecta
    tool: email.send
    effect: external_comm
    args: {}
    run_taint: { untrusted_input: true, private_data: true }
    expect: deny
  - name: over the cap
    tool: pay
    args: { amount: 30 }
    run_id: r1
    counters: { "rule:cap|run:r1": 80 }
    expect: deny
  - name: outside scope
    tool: fs.write
    args: {}
    outside_scope: true
    expect: require_approval
  - name: a shadow run cannot loosen an enforcing policy
    tool: email.send
    effect: external_comm
    args: {}
    run_taint: { untrusted_input: true, private_data: true }
    mode: shadow
    expect: deny
"""
    )
    report = run_cases(policy, cases)
    assert report.ok, report.describe()


# ---------------------------------------------------------------- lint


def codes(policy_yaml: str, tools: tuple[ToolSpec, ...] = ()) -> list[tuple[str, str | None]]:
    return [(w.code, w.rule_id) for w in lint_policy(load_policy(policy_yaml), tools)]


def test_a_clean_policy_has_no_warnings() -> None:
    assert codes(POLICY_YAML) == []


def test_rules_that_can_never_match() -> None:
    found = codes(
        "version: 1\nrules:\n"
        "  - id: a\n    when: { tool: fs.write, tool_glob: 'db.*' }\n"
        "    then: deny\n    reason: r\n"
        "  - id: b\n    when: { effect: read, effect_in: [write] }\n    then: deny\n    reason: r\n"
        "  - id: c\n    when: { resource_ids_any: [nope] }\n    then: deny\n    reason: r\n"
        "  - id: d\n    when: { resource_tags_any: [ghost] }\n    then: deny\n    reason: r\n"
        "  - id: e\n    when: { outbound_findings_any: [secrets] }\n    then: deny\n    reason: r\n"
    )
    assert found == [
        ("never-matches", "a"),
        ("never-matches", "b"),
        ("unknown-resource", "c"),
        ("unknown-tag", "d"),
        ("unknown-finding", "e"),
    ]


def test_system_tags_and_detector_names_are_known() -> None:
    assert (
        codes(
            "version: 1\nrules:\n"
            "  - id: a\n    when: { resource_tags_any: ['arbitr:unresolved-path'] }\n"
            "    then: require_approval\n    reason: r\n"
            "  - id: b\n    when: { outbound_findings_any: [secret, 'pii:card', unscannable] }\n"
            "    then: deny\n    reason: r\n"
        )
        == []
    )


def test_shadowed_rules() -> None:
    found = codes(
        "version: 1\nrules:\n"
        "  - id: broad-deny\n    when: { tool: fs.write }\n    then: deny\n    reason: r\n"
        "  - id: narrow-allow\n    when: { tool: fs.write, principal_in: [alice] }\n"
        "    then: allow\n    reason: r\n"
        "  - id: same-later\n    when: { tool: fs.write }\n    then: deny\n    reason: r\n"
        "  - id: stricter-later\n    when: { tool: db.exec }\n    then: allow\n    reason: r\n"
        "  - id: not-shadowed\n    when: { tool: db.exec, principal_in: [bob] }\n"
        "    then: deny\n    reason: r\n"
    )
    assert found == [("shadowed", "narrow-allow"), ("shadowed", "same-later")]


def test_destructive_tools_without_a_rule() -> None:
    tools = (
        ToolSpec(name="db.drop", effect="destructive"),
        ToolSpec(name="fs.rm", effect="destructive"),
        ToolSpec(name="fs.read", effect="read"),
    )
    policy = (
        "version: 1\nrules:\n  - id: rm\n    when: { tool_glob: 'fs.*' }\n"
        "    then: require_approval\n    reason: r\n"
    )
    assert codes(policy, tools) == [("destructive-without-rule", None)]
    generic = (
        "version: 1\nrules:\n  - id: any-destroy\n    when: { effect: destructive }\n"
        "    then: require_approval\n    reason: r\n"
    )
    assert codes(generic, tools) == []


def test_a_permissive_default_for_destructive_actions_is_flagged() -> None:
    assert codes("version: 1\ndefault: { destructive: allow }\n") == [("permissive-default", None)]


# ---------------------------------------------------------------- CLI


def run(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(cli_main._build_app(), list(args))
    return result.exit_code, result.output


def test_cli_policy_test(files: tuple[Path, Path]) -> None:
    policy, cases = files
    code, out = run("policy", "test", str(policy), str(cases))
    assert code == 0, out
    assert "5 passed, 0 failed" in out
    code, out = run("policy", "test", str(policy), str(cases), "--json")
    assert code == 0
    assert json.loads(out)["passed"] == 5


def test_cli_policy_test_fails_on_a_wrong_case(tmp_path: Path, files: tuple[Path, Path]) -> None:
    policy, _ = files
    bad = tmp_path / "bad.yaml"
    bad.write_text("cases:\n  - {name: x, tool: fs.read, effect: read, expect: deny}\n")
    code, out = run("policy", "test", str(policy), str(bad))
    assert code == 1
    assert "FAIL x" in out


def test_cli_policy_lint(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\ndefault: { destructive: allow }\n")
    code, out = run("policy", "lint", str(policy))
    assert code == 0
    assert "permissive-default" in out
    code, _ = run("policy", "lint", str(policy), "--strict")
    assert code == 1
    code, out = run("policy", "lint", str(policy), "--json")
    assert json.loads(out)[0]["code"] == "permissive-default"


def test_cli_reports_a_bad_policy_without_a_traceback(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 2\n")
    code, out = run("policy", "lint", str(policy))
    assert code == 2
    assert "invalid policy" in out
    assert "Traceback" not in out


def test_cli_policy_schema() -> None:
    code, out = run("policy", "schema")
    assert code == 0
    assert json.loads(out)["title"] == "Arbitr policy"
