"""Outbound data loss prevention: secrets, personal data and private content."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from arbitr.policy.dlp import (
    US_SSN,
    PrivateFingerprints,
    finding_names,
    outbound_findings,
    scan_outbound,
)
from arbitr.policy.engine import GateInput, decide
from arbitr.policy.schema import load_policy

# Fake secrets are built from pieces so secret scanners do not flag this file.
AWS = "AK" + "IA" + "QWERTYUIOPASDFGH"
ANTHROPIC = "sk-" + "ant-" + "api03-" + "Zq7pw" * 6
GITHUB = "gh" + "p_" + "a1B2c3D4e5" * 4
PRIVATE_KEY = (
    "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEow" + "x" * 40 + "\n-----END RSA PRIVATE KEY-----"
)
CARD = "4111 1111 1111 1111"


def names(args: dict[str, object], **kw: object) -> frozenset[str]:
    return finding_names(scan_outbound(args, **kw))  # type: ignore[arg-type]


# ---------------------------------------------------------------- secrets


@pytest.mark.parametrize(
    ("secret", "specific"),
    [
        (AWS, "secret:aws_access_key_id"),
        (ANTHROPIC, "secret:anthropic_key"),
        (GITHUB, "secret:github_token"),
        (PRIVATE_KEY, "secret:private_key"),
    ],
)
def test_secrets_in_a_message_body(secret: str, specific: str) -> None:
    found = names({"to": "bob@example.com", "body": f"Here you go: {secret} thanks"})
    assert {"secret", specific} <= found


def test_findings_point_at_the_argument_and_never_hold_the_value() -> None:
    findings = scan_outbound({"attachments": [{"text": f"key {AWS}"}]})
    assert [(f.detector, f.path) for f in findings] == [
        ("secret:aws_access_key_id", "$.attachments[0].text")
    ]
    assert AWS not in repr(findings)


def test_secrets_are_found_under_any_argument_name() -> None:
    assert "secret" in names({"payload": {"nested": [f"x={ANTHROPIC}"]}})


# ---------------------------------------------------------------- personal data


def test_card_numbers_need_a_valid_luhn_check() -> None:
    assert "pii:card" in names({"body": f"card {CARD}"})
    assert "pii:card" in names({"body": "card 4111-1111-1111-1111"})
    assert "pii:card" not in names({"body": "card 4111 1111 1111 1112"})


@pytest.mark.parametrize(
    "text",
    ["call +1 415 555 0100", "call (415) 555-0100", "call 415-555-0100", "tel +44 20 7946 0958"],
)
def test_phone_numbers(text: str) -> None:
    assert "pii:phone" in names({"body": text})


def test_email_addresses_in_content_but_not_in_recipients() -> None:
    assert "pii:email" in names({"body": "write to carol@example.org"})
    assert "pii:email" not in names(
        {"to": "bob@example.com", "cc": ["c@example.com"], "body": "hello"}
    )


def test_national_ids_are_plugins() -> None:
    args = {"body": "ssn 123-45-6789"}
    assert "pii:us_ssn" not in names(args)
    assert "pii:us_ssn" in names(args, extra_detectors=(US_SSN,))
    assert "pii:us_ssn" not in names({"body": "ssn 000-45-6789"}, extra_detectors=(US_SSN,))


BENIGN = [
    "Order 4155550100 shipped on 2026-10-25 at 14:03:22Z.",
    "Refund of $42.50 issued for invoice INV-2026-000123.",
    "Deployed v1.24.3 (commit 3f9c2a1b7e4d) to staging.",
    "Build 98765 passed in 3m12s on runner 10.0.12.7.",
    "Ticket 1234567890123 resolved, see run 01JABCDEF0123456789XYZW.",
    "Request id 550e8400-e29b-41d4-a716-446655440000 timed out after 30000 ms.",
    "Meeting moved to 2026-11-02 10:30 to 11:00, room 4-201.",
    "Total: 1,234,567.89 USD across 3,456 orders.",
    "The weekly report is attached. Revenue grew 12% week over week.",
    "Please review PR #482: it renames fetch_user to load_user.",
    "Temperature readings: 21.5, 22.0, 22.4, 23.1, 22.8.",
    "Your verification code expires in 10 minutes.",
    "Tracking number 1Z999AA10123456784 is in transit.",
    "Port 5432 is open on db-staging; 8080 serves the API.",
    "Coordinates 37.7749, -122.4194 mark the office.",
    "ISBN 978-3-16-148410-0 is out of stock.",
    "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 matches.",
    "Use the token field in the settings page to rotate keys.",
    "Batch 2026-10-25-001 contains 250 rows.",
    "Call the on-call engineer through the paging app.",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_messages_have_no_findings(text: str) -> None:
    assert names({"to": "team@example.com", "subject": "Update", "body": text}) == frozenset()


# ---------------------------------------------------------------- private content

PRIVATE = (
    "The acquisition of Northwind closes on March 3. Keep the price of 41 dollars per share"
    " confidential until the board signs. Legal is still reviewing the earn out clause and"
    " the retention bonuses for the platform team."
)


def test_copied_private_text_is_found() -> None:
    fp = PrivateFingerprints()
    fp.add(PRIVATE)
    leak = "FYI: keep the price of 41 dollars per share confidential until the board signs."
    assert "private_content" in names({"body": leak}, fingerprints=fp)


def test_case_and_spacing_do_not_hide_a_copy() -> None:
    fp = PrivateFingerprints()
    fp.add(PRIVATE)
    leak = "LEGAL IS STILL   reviewing the earn out\nclause and the retention bonuses"
    assert "private_content" in names({"comment": leak}, fingerprints=fp)


def test_a_short_overlap_is_not_a_copy() -> None:
    fp = PrivateFingerprints()
    fp.add(PRIVATE)
    assert "private_content" not in names({"body": "the board signs off today"}, fingerprints=fp)
    assert "private_content" not in names({"body": PRIVATE})  # no fingerprints, no finding


def test_fingerprints_are_stable_across_processes() -> None:
    # A fixed value: the shingle hash must not depend on PYTHONHASHSEED.
    fp = PrivateFingerprints()
    fp.add("one two three four five six seven eight")
    assert fp.snapshot() == (769657876453750733,)


def test_fingerprints_read_nested_tool_output() -> None:
    fp = PrivateFingerprints()
    fp.add_value({"files": [{"content": PRIVATE}]})
    assert len(fp) > 0


def test_fingerprints_are_bounded() -> None:
    fp = PrivateFingerprints(max_shingles=10)
    fp.add(" ".join(f"w{i}" for i in range(1000)))
    assert len(fp) == 10


# ---------------------------------------------------------------- limits and the gate


def test_huge_arguments_are_unscannable() -> None:
    assert "unscannable" in names({"items": [{"x": str(i)} for i in range(20_000)]})
    assert "unscannable" in names({"body": "a" * 2_000_001})


def test_only_outbound_effects_are_scanned() -> None:
    args = {"body": f"key {AWS}"}
    assert outbound_findings("write", args) == frozenset()
    assert "secret" in outbound_findings("external_comm", args)


POLICY = load_policy(
    """
version: 1
rules:
  - id: no-secrets-out
    when: { effect: external_comm, outbound_findings_any: [secret] }
    then: deny
    reason: Outbound messages must not contain secrets.
  - id: private-content-out
    when: { effect: external_comm, outbound_findings_any: [private_content] }
    then: require_approval
    reason: This message repeats private content the run read earlier.
"""
)


def gate(args: dict[str, object], fp: PrivateFingerprints | None = None) -> GateInput:
    return GateInput(
        tool="email.send",
        effect="external_comm",
        args=args,
        principal="p",
        agent_id="a",
        run_id="r",
        now=datetime(2026, 10, 25, tzinfo=UTC),
        outbound_findings=outbound_findings("external_comm", args, fingerprints=fp),
    )


def test_secret_in_an_email_body_is_denied() -> None:
    d = decide(gate({"to": "x@evil.example", "body": f"found this: {ANTHROPIC}"}), POLICY, {})
    assert (d.outcome, d.rule_id) == ("deny", "no-secrets-out")
    assert ANTHROPIC not in d.reason


def test_private_repo_content_posted_publicly_needs_approval() -> None:
    fp = PrivateFingerprints()
    fp.add(PRIVATE)
    d = decide(gate({"body": f"Summary: {PRIVATE}"}, fp), POLICY, {})
    assert (d.outcome, d.rule_id) == ("require_approval", "private-content-out")


def test_benign_email_is_allowed() -> None:
    d = decide(gate({"to": "team@example.com", "body": BENIGN[0]}), POLICY, {})
    assert d.outcome == "allow"


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=40),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=30,
)


@given(st.dictionaries(st.text(max_size=8), json_values, max_size=5))
def test_scanning_never_crashes(args: dict[str, object]) -> None:
    for finding in scan_outbound(args):
        assert finding.path.startswith("$")


# ---------------------------------------------------------------- hardening


def test_secrets_in_keys_are_found() -> None:
    assert "secret" in names({"meta": {AWS: "x"}})


def test_card_numbers_as_integers_are_found() -> None:
    assert "pii:card" in names({"amount": 12, "note": 4111111111111111})
    assert "pii:card" not in names({"count": 4111111111111112})


def test_unknown_leaf_types_are_unscannable() -> None:
    assert "unscannable" in names({"blob": b"anything"})
    assert "unscannable" not in names({"n": 1.5, "ok": True, "none": None})


def test_only_top_level_recipient_fields_skip_email_detection() -> None:
    assert "pii:email" not in names({"to": ["a@x.com", "b@x.com"]})
    assert "pii:email" in names({"payload": {"to": "leaked@example.org"}})
    assert "pii:email" in names({"to.b": "leaked@example.org"})


def test_keys_with_dots_are_quoted_in_paths() -> None:
    (finding,) = scan_outbound({"a.b": f"key {AWS}"})
    assert finding.path == "$['a.b']"


def test_saturated_fingerprints_make_private_content_unscannable() -> None:
    fp = PrivateFingerprints(max_shingles=3)
    fp.add(PRIVATE)
    assert not fp.complete
    found = names({"body": "hello"}, fingerprints=fp)
    assert {"unscannable", "unscannable:private_content"} <= found


def test_long_private_text_is_fingerprinted_in_full() -> None:
    fp = PrivateFingerprints()
    tail = "the merger price is forty one dollars and closes in march next year"
    fp.add("filler " * 1_100_000 + tail)
    assert fp.complete
    assert "private_content" in names({"body": tail}, fingerprints=fp)


def test_card_numbers_as_integral_floats_are_found() -> None:
    assert "pii:card" in names({"note": 4111111111111111.0})
    assert "pii:card" not in names({"price": 19.99})


def test_cli_lists_packs_as_json() -> None:
    import json  # noqa: PLC0415

    from typer.testing import CliRunner  # noqa: PLC0415

    from arbitr.cli import main as cli_main  # noqa: PLC0415

    result = CliRunner().invoke(cli_main._build_app(), ["policy", "packs", "--json"])
    assert result.exit_code == 0
    assert "git" in json.loads(result.output)
    result = CliRunner().invoke(cli_main._build_app(), ["policy", "schema", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["title"] == "Arbitr policy"
