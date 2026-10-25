"""Redaction of named fields and secret-looking text."""

from __future__ import annotations

import time

import pytest

from arbitr.core.canonical import canonical_json
from arbitr.core.redact import DETECTORS, MARKER_PREFIX, Redactor, luhn_valid

KEY = b"k" * 32
R = Redactor(KEY)

# Every value here must be redacted wherever it appears. Built from pieces so
# the repository's own secret scanner does not flag the test file.
PRIV = "PRIV" + "ATE KEY-----"
SECRETS = {
    "private_key": "-----BEGIN RSA "
    + PRIV
    + "\nMIIEow"
    + "IBAAKCAQEA" * 3
    + "\n-----END RSA "
    + PRIV,
    "unterminated_private_key": "-----BEGIN OPENSSH " + PRIV + "\nb3BlbnNzaC1rZXktdjE",
    "aws_access_key_id": "AKIA" + "IOSFODNN7EXAMPLE",
    "github_token": "ghp_" + "A" * 36,
    "github_pat": "github_pat_" + "11ABCDEFG0" * 3,
    "anthropic_key": "sk-ant-" + "api03-" + "x" * 30,
    "openai_key": "sk-proj-" + "Y" * 40,
    "stripe_key": "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "slack_token": "xoxb-" + "1234567890-abcdefghij",
    "google_api_key": "AIza" + "S" * 35,
    "jwt": "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dozjgNryP4J3jVmNHl0w5N",
    "bearer": "Bearer " + "abcdefghijklmnop1234",
    "card": "4111 1111 1111 1111",
    "card_dashes": "5500-0000-0000-0004",
    "card_plain": "378282246310005",
}


@pytest.mark.parametrize(("name", "secret"), sorted(SECRETS.items()))
def test_detector_catches(name: str, secret: str) -> None:
    out = R.redact_text(f"before {secret} after")
    assert secret not in out, name
    assert MARKER_PREFIX in out
    assert out.startswith("before ")
    assert out.endswith(" after") or name.endswith("private_key")


@pytest.mark.parametrize(
    "text",
    [
        "order 4111111111111112 shipped",  # fails Luhn
        "call 555 0100 today",  # too short
        "sk-short",
        "the word password alone",
        "Bearer short",
        "AKIA lowercase akiaiosfodnn7example",
        "2026-10-25 12:00:00",
        "version 1.2.3.4",
    ],
)
def test_ordinary_text_is_left_alone(text: str) -> None:
    assert R.redact_text(text) == text


def test_assignments_keep_the_label_and_hide_the_value() -> None:
    out = R.redact_text('connect with password="hunter2-very-secret" now')
    assert "hunter2" not in out
    assert out.startswith('connect with password="<redacted:')
    assert out.endswith('" now')


@pytest.mark.parametrize(
    "label", ["password", "PASSWD", "secret", "api_key", "api-key", "auth_token"]
)
def test_assignment_labels(label: str) -> None:
    assert "s3cr3tvalue" not in R.redact_text(f"{label}: s3cr3tvalue")


def test_named_paths_are_redacted_whole() -> None:
    args = {"user": "ann", "card": {"number": "x", "cvv": "123"}, "note": "hello"}
    out = R.redact(args, ["$.card.number", "$.card.cvv"])
    assert out["card"]["number"].startswith(MARKER_PREFIX)  # type: ignore[index]
    assert out["card"]["cvv"].startswith(MARKER_PREFIX)  # type: ignore[index]
    assert out["user"] == "ann"  # type: ignore[index]
    assert args["card"] == {"number": "x", "cvv": "123"}


def test_path_can_redact_whole_subtrees() -> None:
    out = R.redact({"creds": {"a": 1, "b": [2]}}, ["$.creds"])
    assert isinstance(out, dict)
    assert out["creds"].startswith(MARKER_PREFIX)


def test_secrets_in_keys_are_redacted() -> None:
    secret = SECRETS["github_token"]
    out = R.redact({secret: "value"})
    assert secret not in canonical_json(out)


def test_secrets_nested_in_lists() -> None:
    secret = SECRETS["stripe_key"]
    out = R.redact({"a": [[{"b": f"x {secret}"}]]})
    assert secret not in canonical_json(out)


def test_redaction_is_idempotent() -> None:
    value = {"t": f"{SECRETS['jwt']} and {SECRETS['card']}", "p": "x"}
    once = R.redact(value, ["$.p"])
    assert R.redact(once) == once


def test_fake_marker_prefix_does_not_hide_a_secret() -> None:
    secret = SECRETS["anthropic_key"]
    out = R.redact_text(f"{MARKER_PREFIX} {secret}")
    assert secret not in out


def test_markers_are_keyed() -> None:
    assert Redactor(KEY).marker("4111") == Redactor(KEY).marker("4111")
    assert Redactor(KEY).marker("4111") != Redactor(b"j" * 32).marker("4111")
    assert Redactor(KEY).marker("4111") != Redactor(KEY).marker("4112")


def test_short_key_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        Redactor(b"short")


def test_detection_can_be_turned_off() -> None:
    secret = SECRETS["openai_key"]
    assert Redactor(KEY, detect=False).redact({"a": secret}) == {"a": secret}


def test_ordinary_scalars_pass_through_and_card_integers_do_not() -> None:
    value = {"n": 42, "id": 4111111111111112, "f": 1.5, "b": True, "z": None}
    assert R.redact(value) == value
    card = R.redact({"n": 4111111111111111})
    assert isinstance(card, dict)
    assert str(card["n"]).startswith(MARKER_PREFIX)


@pytest.mark.parametrize(
    ("digits", "valid"),
    [
        ("4111111111111111", True),
        ("378282246310005", True),
        ("0", True),
        ("1", False),
        ("79927398713", True),
    ],
)
def test_luhn(digits: str, valid: bool) -> None:
    assert luhn_valid(digits) is valid


@pytest.mark.parametrize("unit", ["a-", "aa", "1.", "x:", "a@"])
def test_detectors_run_in_linear_time(unit: str) -> None:
    text = unit * 100_000
    started = time.perf_counter()
    for _, pattern in DETECTORS:
        pattern.search(text)
    assert time.perf_counter() - started < 2.0


def test_url_credentials_after_a_long_scheme_like_prefix_are_redacted() -> None:
    redactor = Redactor(b"k" * 32)
    hidden = "Zq7pw-" + "hunter2"
    text = "x" * 60 + "://bob:" + hidden + "@db.example.com/app"
    assert hidden not in str(redactor.redact(text))
