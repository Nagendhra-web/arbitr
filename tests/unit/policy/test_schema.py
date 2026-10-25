"""Policy files: loading, validation and the published JSON Schema."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from arbitr.core.errors import PolicyError
from arbitr.policy.schema import (
    Policy,
    json_schema,
    load_policy,
    parse_duration,
)

EXAMPLE = """
version: 1
mode: enforce
default:
  read: allow
  write: allow
  destructive: require_approval
  external_comm: allow
  financial: require_approval
on_unknown: require_approval
approval:
  wait_seconds: 0
  expires_after: 15m

resources:
  - id: prod-db
    match: { kind: database, uri_glob: "postgres://*prod*" }
    tags: [production, critical]
  - id: backups
    match: { kind: path, glob: "/var/backups/**" }
    tags: [backup, critical]
  - id: public-repos
    match: { kind: github_repo, attrs: { visibility: public } }
    tags: [public]

rules:
  - id: no-destroy-critical
    when:
      effect: destructive
      resource_tags_any: [critical]
    then: deny
    reason: "Destructive actions on critical resources are never allowed for agents."
    always_enforce: true

  - id: code-freeze
    when:
      effect_in: [write, destructive]
      resource_tags_any: [production]
      time_window: { cron_active: freeze }
    then: deny
    reason: "Production is in a code freeze."

  - id: big-refunds
    when:
      tool: payments.refund
      args:
        - { path: "$.amount", op: gt, value: 100 }
    then: require_approval
    reason: "Refunds over 100 need a human."

  - id: refund-daily-cap
    when: { tool: payments.refund }
    budget:
      scope: [principal, day]
      sum_path: "$.amount"
      limit: 500
    then_exceeded: deny
    reason: "Daily refund cap reached."

  - id: lethal-trifecta
    when:
      effect: external_comm
      run_taint: { untrusted_input: true, private_data: true }
    then: require_approval
    reason: "Run read untrusted input and private data, outbound message needs a human."

  - id: mass-email
    when: { tool: email.send }
    budget: { scope: [run], count: true, limit: 20 }
    then_exceeded: deny
    reason: "Too many emails in one run."

windows:
  freeze: { start: "2026-12-20T00:00:00Z", end: "2027-01-05T00:00:00Z" }
"""


def test_example_policy_loads() -> None:
    policy = load_policy(EXAMPLE)
    assert policy.mode == "enforce"
    assert [r.id for r in policy.rules][:2] == ["no-destroy-critical", "code-freeze"]
    assert policy.default.destructive == "require_approval"
    assert policy.approval.expires_after == timedelta(minutes=15)
    assert policy.windows["freeze"].end == datetime(2027, 1, 5, tzinfo=UTC)
    cap = policy.rules[3]
    assert cap.budget is not None
    assert (cap.budget.scope, cap.budget.sum_path, cap.budget.limit) == (
        ("principal", "day"),
        "$.amount",
        500,
    )
    assert cap.then_exceeded == "deny"


def test_minimal_policy_uses_safe_defaults() -> None:
    policy = load_policy("version: 1\n")
    assert policy.mode == "enforce"
    assert policy.default.read == "allow"
    assert policy.default.destructive == "require_approval"
    assert policy.default.financial == "require_approval"
    assert policy.on_unknown == "require_approval"
    assert policy.rules == ()


def test_load_from_file(tmp_path: Path) -> None:
    path = tmp_path / "arbitr.yaml"
    path.write_text(EXAMPLE, encoding="utf-8")
    assert load_policy(path).rules[0].id == "no-destroy-critical"


def bad(snippet: str) -> str:
    return "version: 1\n" + snippet


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("version: 2\n", "version"),
        ("- just a list\n", "mapping"),
        ("version: 1\nversion: 1\n", "duplicate"),
        ("version: 1\nmode: yolo\n", "mode"),
        ("version: 1\nsurprise: true\n", "surprise"),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x}, then: deny, reason: r}\n"
                "  - {id: a, when: {tool: y}, then: deny, reason: r}\n"
            ),
            "duplicate rule id",
        ),
        (bad("rules:\n  - {id: Bad Id, when: {tool: x}, then: deny, reason: r}\n"), "id"),
        (bad("rules:\n  - {id: a, when: {tool: x}, reason: r}\n"), "then"),
        (bad("rules:\n  - {id: a, when: {tool: x}, then: deny}\n"), "reason"),
        (bad("rules:\n  - {id: a, when: {tool: x}, then: maybe, reason: r}\n"), "then"),
        (bad("rules:\n  - {id: a, when: {}, then: deny, reason: r}\n"), "at least one"),
        (
            bad("rules:\n  - {id: a, when: {tool: x, colour: red}, then: deny, reason: r}\n"),
            "colour",
        ),
        (bad("rules:\n  - {id: a, when: {effect: nuke}, then: deny, reason: r}\n"), "effect"),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x, args: [{path: amount, op: gt, value: 1}]},"
                " then: deny, reason: r}\n"
            ),
            "path",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x, args: [{path: $.a, op: explode}]},"
                " then: deny, reason: r}\n"
            ),
            "op",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x, time_window: {cron_active: nope}},"
                " then: deny, reason: r}\n"
            ),
            "window",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x}, budget: {scope: [run], limit: 5},"
                " then_exceeded: deny, reason: r}\n"
            ),
            "sum_path or count",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x},"
                " budget: {scope: [run], count: true, limit: 5}, reason: r}\n"
            ),
            "then_exceeded",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x}, budget: {scope: [galaxy], count: true,"
                " limit: 5}, then_exceeded: deny, reason: r}\n"
            ),
            "scope",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x}, budget: {scope: [run], count: true,"
                " limit: 0}, then_exceeded: deny, reason: r}\n"
            ),
            "limit",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x}, then: deny, budget: {scope: [run],"
                " count: true, limit: 5}, then_exceeded: deny, reason: r}\n"
            ),
            "either",
        ),
        (
            bad("windows:\n  w: {start: '2027-01-01T00:00:00Z', end: '2026-01-01T00:00:00Z'}\n"),
            "end",
        ),
        (
            bad("windows:\n  w: {start: '2027-01-01T00:00:00', end: '2028-01-01T00:00:00Z'}\n"),
            "timezone",
        ),
        (bad("approval: {expires_after: 15 parsecs}\n"), "duration"),
        (bad("resources:\n  - {id: r, match: {}, tags: [x]}\n"), "kind"),
        (
            bad(
                "resources:\n  - {id: r, match: {kind: path}, tags: []}\n"
                "  - {id: r, match: {kind: path}, tags: []}\n"
            ),
            "duplicate resource id",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x, args: [{path: $.a, op: regex,"
                " value: '(?=a)b'}]}, then: deny, reason: r}\n"
            ),
            "regex",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x, args: [{path: $.a, op: in, value: 3}]},"
                " then: deny, reason: r}\n"
            ),
            "list",
        ),
        (
            bad(
                "rules:\n  - {id: a, when: {tool: x, args: [{path: $.a, op: gt, value: abc}]},"
                " then: deny, reason: r}\n"
            ),
            "number",
        ),
    ],
)
def test_invalid_policies_are_refused_with_a_clear_message(text: str, message: str) -> None:
    with pytest.raises(PolicyError) as err:
        load_policy(text)
    assert message.lower() in str(err.value).lower()


def test_yaml_tags_cannot_run_code() -> None:
    with pytest.raises(PolicyError):
        load_policy("version: 1\nx: !!python/object/apply:os.system ['echo hi']\n")


def test_policy_is_immutable() -> None:
    policy = load_policy(EXAMPLE)
    with pytest.raises(Exception):  # noqa: B017, PT011
        policy.mode = "shadow"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("15m", timedelta(minutes=15)),
        ("30s", timedelta(seconds=30)),
        ("2h", timedelta(hours=2)),
        ("1d", timedelta(days=1)),
        ("90", timedelta(seconds=90)),
    ],
)
def test_durations(text: str, expected: timedelta) -> None:
    assert parse_duration(text) == expected


def test_published_json_schema_is_current() -> None:
    """The schema file editors use must match the model; regenerate it when this fails."""
    published = (
        Path(__file__).resolve().parents[3] / "src" / "arbitr" / "policy" / "policy.schema.json"
    )
    assert json.loads(published.read_text(encoding="utf-8")) == json_schema()


def test_json_schema_describes_rules() -> None:
    schema = json_schema()
    assert schema["title"] == "Arbitr policy"
    assert "rules" in schema["properties"]


def test_policy_round_trips_through_its_model() -> None:
    policy = load_policy(EXAMPLE)
    again = Policy.model_validate(policy.model_dump())
    assert again == policy
