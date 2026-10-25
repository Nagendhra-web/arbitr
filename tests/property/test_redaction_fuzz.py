"""Fuzz: secrets planted anywhere in random arguments never survive redaction."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from arbitr.core.canonical import canonicalize
from arbitr.core.redact import Redactor

R = Redactor(b"fuzz-key-" * 4)

SECRET_SHAPES = st.sampled_from(
    [
        lambda s: "AKIA" + s.upper().ljust(16, "Q")[:16],
        lambda s: "ghp_" + (s * 40)[:36],
        lambda s: "sk-ant-api03-" + (s * 30)[:30],
        lambda s: "sk_live_" + (s * 20)[:20],
        lambda s: "xoxb-" + (s * 12)[:12],
        lambda s: "Bearer " + (s * 20)[:20],
        lambda s: "-----BEGIN PRIVATE KEY-----\n" + (s * 10)[:40] + "\n-----END PRIVATE KEY-----",
    ]
)
TOKEN = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=4, max_size=12)

filler = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=20)
plain = st.recursive(
    st.none() | st.booleans() | st.integers(-1000, 1000) | filler,
    lambda c: st.lists(c, max_size=4) | st.dictionaries(filler, c, max_size=4),
    max_leaves=15,
)


def plant(value: object, secret: str, choice: int) -> object:
    """Put the secret into the structure: as a value, inside text, or as a key."""
    if choice == 0:
        return {"wrapped": value, "s": secret}
    if choice == 1:
        return {"note": f"see {secret} here", "rest": value}
    if choice == 2:
        return {secret: value}
    return [value, [{"deep": [f"{secret}"]}]]


@settings(max_examples=300)
@given(plain, SECRET_SHAPES, TOKEN, st.integers(0, 3))
def test_planted_secret_never_survives(
    value: object, shape: object, token: str, choice: int
) -> None:
    secret = shape(token)  # type: ignore[operator]
    out = R.redact(plant(value, secret, choice))
    stored = canonicalize(out)
    assert secret.encode() not in stored
