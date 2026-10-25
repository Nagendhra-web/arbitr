"""Canonical JSON (RFC 8785, JSON Canonicalization Scheme).

The vectors below are the published examples from RFC 8785: the number
serialization table (Appendix B) and the primitive and sorting examples
(section 3.2).
"""

from __future__ import annotations

import json
import math
import struct

import pytest

from arbitr.core.canonical import canonical_json, canonicalize, sha256_hex
from arbitr.core.errors import CanonicalizationError

# RFC 8785 Appendix B: IEEE 754 bit pattern -> expected serialization.
NUMBER_VECTORS = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]

# Appendix B also lists NaN and Infinity, which have no JSON form.
INVALID_NUMBER_BITS = ["7fffffffffffffff", "7ff0000000000000", "fff0000000000000"]


def from_bits(hexbits: str) -> float:
    value: float = struct.unpack(">d", bytes.fromhex(hexbits))[0]
    return value


@pytest.mark.parametrize(("bits", "expected"), NUMBER_VECTORS)
def test_number_vectors(bits: str, expected: str) -> None:
    assert canonical_json(from_bits(bits)) == expected


@pytest.mark.parametrize("bits", INVALID_NUMBER_BITS)
def test_nan_and_infinity_are_rejected(bits: str) -> None:
    with pytest.raises(CanonicalizationError, match="NaN or Infinity"):
        canonicalize(from_bits(bits))


def test_rfc_primitive_example() -> None:
    """RFC 8785 section 3.2.2."""
    source = (
        '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
        ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
        ' "literals": [null, true, false]}'
    )
    expected = (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert canonical_json(json.loads(source)) == expected


def test_rfc_sorting_example() -> None:
    """RFC 8785 section 3.2.3: keys sort by UTF-16 code units, not by locale."""
    source = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    order = [k for k, _ in json.loads(canonical_json(source), object_pairs_hook=list)]
    assert order == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]


def test_nested_structures_sort_recursively() -> None:
    source = {"1": {"f": {"f": "hi", "F": 5}, "\n": 56.0}, "10": {}, "": "empty", "a": {}}
    assert (
        canonical_json(source) == '{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"a":{}}'
    )


def test_string_escaping() -> None:
    value = 'q"b\\s/c\x00\x1f\x7f\b\t\n\f\r\u2028'
    assert canonical_json(value) == '"q\\"b\\\\s/c\\u0000\\u001f\x7f\\b\\t\\n\\f\\r\u2028"'


def test_unicode_is_not_normalized() -> None:
    """RFC 8785 keeps strings exactly as given: A + combining ring stays two code points."""
    assert canonical_json("Å") == '"Å"'


def test_output_is_utf8_bytes() -> None:
    assert canonicalize({"k": "é"}) == '{"k":"é"}'.encode()


def test_tuples_are_arrays() -> None:
    assert canonical_json((1, [2, (3,)])) == "[1,[2,[3]]]"


@pytest.mark.parametrize(
    "value",
    [
        {1: "non-string key"},
        {"k": {1, 2}},
        {"k": object()},
        b"bytes",
        "\ud800 lone surrogate",
        {"\udfff": "lone surrogate in a key"},
    ],
)
def test_rejects_values_without_a_json_form(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


@pytest.mark.parametrize("n", [2**53, -(2**53), 2**53 - 1, 0, -1, 10**15])
def test_safe_integers_are_exact(n: int) -> None:
    assert canonical_json(n) == str(n)


@pytest.mark.parametrize("n", [2**53 + 1, -(2**53) - 1, 10**30 + 1, 2**68, -(2**60), 10**21])
def test_integers_that_would_change_are_rejected(n: int) -> None:
    """Rounding would let two different arguments hash the same, so refuse instead.

    2**68 is an exact double, but its canonical form 295147905179352830000 reads
    back as a different integer, so it is rejected too.
    """
    with pytest.raises(CanonicalizationError, match="cannot be represented exactly"):
        canonicalize(n)


@pytest.mark.parametrize("n", [295147905179352830000, 29094978564211190, -29094978564211190])
def test_large_integers_whose_digits_survive_are_accepted(n: int) -> None:
    assert canonical_json(n) == str(n)
    assert json.loads(canonical_json(n)) == n


def test_booleans_are_not_numbers() -> None:
    assert canonical_json([True, False, 1, 0]) == "[true,false,1,0]"


def test_int_and_equal_float_canonicalize_the_same() -> None:
    assert canonical_json(56) == canonical_json(56.0) == "56"


def test_sha256_hex() -> None:
    assert sha256_hex({"b": 1, "a": 2}) == sha256_hex({"a": 2, "b": 1})
    assert len(sha256_hex([])) == 64
    assert sha256_hex(1) != sha256_hex("1")


def test_deep_nesting_is_rejected() -> None:
    value: list[object] = []
    for _ in range(200):
        value = [value]
    with pytest.raises(CanonicalizationError, match="nested"):
        canonicalize(value)


def test_negative_zero_is_zero() -> None:
    assert canonical_json(-0.0) == "0"
    assert math.copysign(1.0, -0.0) == -1.0
