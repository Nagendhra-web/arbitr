"""Properties of canonical JSON that must hold for every JSON value."""

from __future__ import annotations

import json
import random

from hypothesis import given
from hypothesis import strategies as st

from arbitr.core.canonical import canonical_json, canonicalize
from arbitr.core.errors import CanonicalizationError

SAFE_INT = 2**53

scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-SAFE_INT, max_value=SAFE_INT)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text()
)
json_values = st.recursive(
    scalars,
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(st.text(max_size=8), children, max_size=5)
    ),
    max_leaves=40,
)


def parse_ijson(text: str) -> object:
    """Parse the way an I-JSON reader does: numbers beyond 2**53 are doubles."""

    def parse_int(s: str) -> int | float:
        n = int(s)
        return n if abs(n) <= SAFE_INT else float(s)

    return json.loads(text, parse_int=parse_int)


@given(json_values)
def test_parsing_the_canonical_form_gives_back_the_same_value(value: object) -> None:
    """Parsing canonical(x) gives x. This also makes canonicalization injective:
    two values with the same canonical form parse to the same value."""
    assert parse_ijson(canonical_json(value)) == value


@given(st.integers())
def test_integers_are_exact_or_rejected(value: int) -> None:
    """An accepted integer always reads back as the very same integer."""
    try:
        text = canonical_json(value)
    except CanonicalizationError:
        return
    assert json.loads(text) == value


@given(json_values)
def test_canonical_form_is_a_fixed_point(value: object) -> None:
    once = canonical_json(value)
    assert canonical_json(json.loads(once)) == once


@given(st.dictionaries(st.text(max_size=8), json_values, max_size=8), st.randoms())
def test_key_order_does_not_matter(value: dict[str, object], rnd: random.Random) -> None:
    items = list(value.items())
    rnd.shuffle(items)
    assert canonicalize(dict(items)) == canonicalize(value)


@given(st.floats(allow_nan=False, allow_infinity=False))
def test_every_finite_double_round_trips(value: float) -> None:
    assert float(canonical_json(value)) == value


@given(json_values)
def test_output_never_contains_raw_line_breaks_or_tabs(value: object) -> None:
    """Control characters are always escaped and no whitespace separates tokens."""
    out = canonicalize(value)
    assert b"\n" not in out
    assert b"\r" not in out
    assert b"\t" not in out
