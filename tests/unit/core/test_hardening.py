"""Redaction, intent and canonical JSON hardening.

Each test reproduces a way a secret could leak or a hash could be fooled.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from arbitr.core.canonical import canonical_json
from arbitr.core.intent import build_intent
from arbitr.core.redact import MARKER_PREFIX, Redactor
from arbitr.core.spec import ToolSpec

R = Redactor(b"hardening-key-01" * 2)
SPEC = ToolSpec(name="tool.x", effect="write")


# ---------------------------------------------------------------- redaction by key name


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Password",
        "PASSWD",
        "pwd",
        "pw",
        "secret",
        "token",
        "api_key",
        "api-key",
        "apikey",
        "access_key",
        "private_key",
        "client_secret",
        "authorization",
        "cookie",
        "set-cookie",
        "Set_Cookie",
        "db_password",
        "refresh_token",
        "aws_secret",
    ],
)
def test_sensitive_key_names_redact_the_whole_value(key: str) -> None:
    out = R.redact({key: "hunter2", "user": "ann"})
    assert isinstance(out, dict)
    assert out[key].startswith(MARKER_PREFIX)
    assert out["user"] == "ann"


@pytest.mark.parametrize("value", [12345678, ["a", "b"], {"nested": "x"}, None])
def test_sensitive_keys_redact_any_value_type(value: object) -> None:
    out = R.redact({"secret": value})
    assert isinstance(out, dict)
    assert str(out["secret"]).startswith(MARKER_PREFIX)


@pytest.mark.parametrize("key", ["tokenizer", "user", "keyboard", "idempotency_key", "monkey"])
def test_ordinary_key_names_are_not_redacted(key: str) -> None:
    assert R.redact({key: "plain"}) == {key: "plain"}


def test_sensitive_keys_found_at_any_depth() -> None:
    out = R.redact({"a": [{"b": {"Authorization": "Basic Zm9vOmJhcg=="}}]})
    assert "Zm9vOmJhcg" not in canonical_json(out)


def test_json_quoted_assignment_in_text() -> None:
    text = '{"pass' + 'word": "' + "hunter2" + '-is-long", "user": "ann"}'
    out = R.redact_text(text)
    assert "hunter2" not in out
    assert '"user": "ann"' in out


def test_basic_auth_in_text() -> None:
    out = R.redact_text("Authorization: Basic Zm9vOmJhcmJhemJheg==")
    assert "Zm9vOmJhcmJhemJheg" not in out


@pytest.mark.parametrize("n", [4111111111111111, 378282246310005])
def test_card_numbers_as_integers(n: int) -> None:
    out = R.redact({"card": n, "other": 4111111111111112})
    assert isinstance(out, dict)
    assert str(out["card"]).startswith(MARKER_PREFIX)
    assert out["other"] == 4111111111111112  # fails Luhn, kept


def test_booleans_and_small_ints_are_kept() -> None:
    assert R.redact({"a": True, "b": 42, "c": 1.5}) == {"a": True, "b": 42, "c": 1.5}


# ---------------------------------------------------------------- intents


def test_intent_snapshot_ignores_later_mutation() -> None:
    args: dict[str, object] = {"amount": 40, "items": [1, 2]}
    intent = build_intent(SPEC, args, run_id="r", principal="p")
    before = intent.intent_hash
    args["amount"] = 9999
    args["items"].append(3)  # type: ignore[attr-defined]
    assert intent.args == {"amount": 40, "items": [1, 2]}
    assert intent.intent_hash == before


def test_intent_args_are_a_copy_each_time() -> None:
    intent = build_intent(SPEC, {"items": [1]}, run_id="r", principal="p")
    got = intent.args
    got["items"].append(2)  # type: ignore[attr-defined]
    assert intent.args == {"items": [1]}


def test_custom_mapping_is_read_once() -> None:
    """A mapping that changes between reads cannot split the hash from the stored value."""

    class Shifty(dict[str, object]):
        reads = 0

        def items(self) -> list[tuple[str, object]]:  # type: ignore[override]
            Shifty.reads += 1
            return [("amount", Shifty.reads)]

        def __iter__(self) -> Iterator[str]:
            return iter(["amount"])

        def __getitem__(self, key: str) -> object:
            Shifty.reads += 1
            return Shifty.reads

    intent = build_intent(SPEC, Shifty(), run_id="r", principal="p")
    first = intent.args
    assert intent.args == first
    from arbitr.core.intent import compute_intent_hash  # noqa: PLC0415

    assert intent.intent_hash == compute_intent_hash("tool.x", first, "r", "p")


def test_spec_redact_paths_travel_with_the_intent() -> None:
    spec = ToolSpec(name="t", effect="write", redact=["$.card"])
    intent = build_intent(spec, {"card": "x"}, run_id="r", principal="p")
    assert intent.redact_paths == ("$.card",)


# ---------------------------------------------------------------- canonical injection


def test_int_subclass_cannot_inject_text() -> None:
    class Evil(int):
        def __str__(self) -> str:
            return '1,"admin":true'

        __repr__ = __str__

    assert canonical_json({"a": Evil(1)}) == '{"a":1}'


def test_str_subclass_cannot_inject_text() -> None:
    class Evil(str):
        __slots__ = ()

        def __iter__(self) -> Iterator[str]:
            return iter('x","admin":"y')

        def __str__(self) -> str:
            return 'x","admin":"y'

    assert canonical_json({"a": Evil("ok")}) == '{"a":"ok"}'
