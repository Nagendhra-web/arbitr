"""Policy packs: each one passes its own case table and lints clean."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from arbitr.cli import main as cli_main
from arbitr.core.errors import PolicyError
from arbitr.policy.lint import lint_policy
from arbitr.policy.packs import PACKS, pack_cases_text, pack_text, starter_policy
from arbitr.policy.schema import load_policy, load_yaml
from arbitr.policy.testing import load_cases, run_cases

MIN_CASES = 30


@pytest.mark.parametrize("pack", PACKS)
def test_pack_passes_its_case_table(pack: str) -> None:
    policy = load_policy(f"version: 1\ninclude: [{pack}]\n")
    cases = load_cases(pack_cases_text(pack))
    assert len(cases) >= MIN_CASES
    report = run_cases(policy, cases)
    assert report.ok, report.describe()


@pytest.mark.parametrize("pack", PACKS)
def test_pack_lints_clean(pack: str) -> None:
    policy = load_policy(f"version: 1\ninclude: [{pack}]\n")
    assert [w.to_dict() for w in lint_policy(policy)] == []


@pytest.mark.parametrize("pack", PACKS)
def test_pack_ids_carry_the_pack_name(pack: str) -> None:
    data = load_yaml(pack_text(pack), pack)
    ids = [r["id"] for r in data.get("rules", [])] + [r["id"] for r in data.get("resources", [])]
    assert ids
    assert all(i.startswith(f"{pack}.") for i in ids)
    assert all(r.get("reason") for r in data.get("rules", []))


def test_all_packs_load_together() -> None:
    policy = load_policy(f"version: 1\ninclude: [{', '.join(PACKS)}]\n")
    ids = [r.id for r in policy.rules]
    assert len(ids) == len(set(ids))
    problems = [w for w in lint_policy(policy) if w.code not in ("shadowed",)]
    assert problems == []


def test_every_pack_case_table_passes_with_all_packs_loaded() -> None:
    """Packs do not loosen each other: each pack's denials survive the others."""
    policy = load_policy(f"version: 1\ninclude: [{', '.join(PACKS)}]\n")
    for pack in PACKS:
        for case in load_cases(pack_cases_text(pack)):
            if case.expect != "deny":
                continue
            result = run_cases(policy, [case])
            assert result.results[0].decision.outcome == "deny", (pack, case.name)


def test_a_policy_rule_replaces_the_pack_rule_with_the_same_id() -> None:
    policy = load_policy(
        "version: 1\ninclude: [git]\nrules:\n"
        "  - id: git.push-protected\n    when: { tool: never.used }\n    then: deny\n"
        "    reason: Replaced.\n"
    )
    rule = next(r for r in policy.rules if r.id == "git.push-protected")
    assert rule.reason == "Replaced."
    assert [r.id for r in policy.rules].count("git.push-protected") == 1


def test_exclude_rules_drops_pack_rules() -> None:
    policy = load_policy("version: 1\ninclude: [git]\nexclude_rules: [git.push-protected]\n")
    assert "git.push-protected" not in {r.id for r in policy.rules}
    with pytest.raises(PolicyError, match="do not exist"):
        load_policy("version: 1\ninclude: [git]\nexclude_rules: [git.nope]\n")


def test_unknown_packs_are_refused() -> None:
    with pytest.raises(PolicyError, match="unknown pack"):
        load_policy("version: 1\ninclude: [nope]\n")


def test_policy_resources_override_pack_resources() -> None:
    policy = load_policy(
        "version: 1\ninclude: [databases]\nresources:\n"
        "  - id: databases.production\n"
        "    match: { kind: database, uri_glob: '*live*' }\n"
        "    tags: [production, database]\n"
    )
    resource = next(r for r in policy.resources if r.id == "databases.production")
    assert resource.match.uri_glob == "*live*"


def test_starter_policy_loads() -> None:
    text = starter_policy(["databases", "git", "filesystem"])
    policy = load_policy(text)
    assert policy.include == (
        "databases",
        "git",
        "filesystem",
        "email-and-messaging",
        "lethal-trifecta",
    )
    assert starter_policy(["lethal-trifecta"]).count("lethal-trifecta") == 1
    with pytest.raises(ValueError, match="unknown packs"):
        starter_policy(["nope"])


def test_cli_lists_packs() -> None:
    result = CliRunner().invoke(cli_main._build_app(), ["policy", "packs"])
    assert result.exit_code == 0
    assert all(pack in result.output for pack in PACKS)
