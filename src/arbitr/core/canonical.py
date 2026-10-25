"""Canonical JSON, RFC 8785 (JSON Canonicalization Scheme).

Every hash Arbitr computes (intent hashes, idempotency keys, the audit chain)
is taken over canonical JSON, so two semantically equal values always hash the
same and different values never do.

The rules, briefly: object keys are sorted by their UTF-16 code units, there
is no insignificant whitespace, strings keep their exact code points with only
the escapes JSON requires, and numbers are written the way ECMAScript writes
an IEEE 754 double. Values that have no exact JSON form are rejected rather
than approximated.

Example:
    >>> canonical_json({"b": [1, 2.50, None], "a": "é"})
    '{"a":"é","b":[1,2.5,null]}'
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from decimal import Decimal
from typing import Final

from arbitr.core.errors import CanonicalizationError

MAX_DEPTH: Final = 128
"""Deepest nesting accepted. Agent arguments never need more; attackers might try."""

_MAX_EXACT_INT: Final = 2**53
_SURROGATES: Final = range(0xD800, 0xE000)
_FIRST_PRINTABLE: Final = 0x20
# ECMAScript Number.prototype.toString switches to exponent form outside these.
_MAX_PLAIN_EXPONENT: Final = 21
_MIN_PLAIN_EXPONENT: Final = -6

_SHORT_ESCAPES: Final = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def canonicalize(value: object) -> bytes:
    """Return the RFC 8785 canonical form of ``value`` as UTF-8 bytes.

    Accepts ``None``, ``bool``, ``int``, ``float``, ``str``, mappings with string
    keys, and lists or tuples, nested up to ``MAX_DEPTH``.

    Raises:
        CanonicalizationError: the value has no exact JSON form (NaN, infinity,
            an integer a double cannot hold, a non-string key, a lone surrogate,
            an unsupported type, or nesting deeper than ``MAX_DEPTH``).

    Example:
        >>> canonicalize([True, None, "x"])
        b'[true,null,"x"]'
    """
    parts: list[str] = []
    _write(value, parts, 0)
    return "".join(parts).encode("utf-8")


def canonical_json(value: object) -> str:
    """Return the canonical form of ``value`` as a string.

    Example:
        >>> canonical_json({"z": 1, "a": 1e21})
        '{"a":1e+21,"z":1}'
    """
    return canonicalize(value).decode("utf-8")


def sha256_hex(value: object) -> str:
    """Return the hex SHA-256 of the canonical form of ``value``.

    Example:
        >>> sha256_hex({"a": 1}) == sha256_hex({"a": 1.0})
        True
    """
    return hashlib.sha256(canonicalize(value)).hexdigest()


def _write(value: object, out: list[str], depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"value is nested deeper than {MAX_DEPTH} levels")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    # Scalars are converted to their exact base type first, so a subclass that
    # overrides __str__, __repr__, __iter__ or __abs__ cannot change the output.
    elif isinstance(value, str):
        out.append(_string(str.__str__(value)))
    elif isinstance(value, int):
        out.append(_integer(int.__index__(value)))
    elif isinstance(value, float):
        out.append(_number(float.__float__(value)))
    elif isinstance(value, Mapping):
        _write_object(value, out, depth)
    elif isinstance(value, list | tuple):
        _write_array(value, out, depth)
    else:
        raise CanonicalizationError(f"{type(value).__name__} has no JSON form")


def _write_object(value: Mapping[object, object], out: list[str], depth: int) -> None:
    # Read the mapping exactly once, and use plain-str keys from then on.
    pairs: list[tuple[str, object]] = []
    for key, item in list(value.items()):
        if not isinstance(key, str):
            raise CanonicalizationError(f"object keys must be strings, not {type(key).__name__}")
        pairs.append((str.__str__(key), item))
    out.append("{")
    for i, (key, item) in enumerate(sorted(pairs, key=lambda p: _utf16_key(p[0]))):
        if i:
            out.append(",")
        out.append(_string(key))
        out.append(":")
        _write(item, out, depth + 1)
    out.append("}")


def _write_array(value: list[object] | tuple[object, ...], out: list[str], depth: int) -> None:
    out.append("[")
    for i, item in enumerate(value):
        if i:
            out.append(",")
        _write(item, out, depth + 1)
    out.append("]")


def _utf16_key(key: str) -> bytes:
    """Sort key: big-endian UTF-16 bytes compare in UTF-16 code unit order."""
    return key.encode("utf-16-be", "surrogatepass")


def _string(value: str) -> str:
    out = ['"']
    # str.__str__ gives the plain string even for a subclass that overrides iteration.
    for ch in str.__str__(value):
        code = ord(ch)
        if code in _SURROGATES:
            raise CanonicalizationError("strings must not contain lone surrogates")
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif code < _FIRST_PRINTABLE:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _integer(value: int) -> str:
    """Integers beyond 2**53 are accepted only when nothing is lost.

    JSON numbers are IEEE 754 doubles. A large integer is accepted only if the
    double nearest to it serializes to exactly the same digits, so parsing the
    canonical form gives back the very same integer. Anything else would let two
    different arguments share one hash, so it is rejected instead of rounded.
    """
    if -_MAX_EXACT_INT <= value <= _MAX_EXACT_INT:
        return int.__repr__(value)  # never a subclass override
    try:
        text = _number(float(value))
    except (OverflowError, CanonicalizationError):
        text = ""
    if text != int.__repr__(value):
        raise CanonicalizationError(
            f"integer {value} cannot be represented exactly as an IEEE 754 double; "
            "pass it as a string"
        )
    return text


def _number(value: float) -> str:
    """Serialize a double the way ECMAScript Number.prototype.toString does."""
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("NaN or Infinity has no JSON form")
    if value == 0:
        return "0"  # covers -0.0 too
    sign = "-" if value < 0 else ""
    # repr() gives the shortest digit string that round-trips, as ECMAScript does.
    parts = Decimal(repr(abs(value))).normalize().as_tuple()
    digits = "".join(str(d) for d in parts.digits)
    exponent = int(parts.exponent)  # always an int for a finite value
    k = len(digits)
    n = exponent + k  # value == 0.digits * 10**n
    if k <= n <= _MAX_PLAIN_EXPONENT:
        body = digits + "0" * (n - k)
    elif 0 < n <= _MAX_PLAIN_EXPONENT:
        body = digits[:n] + "." + digits[n:]
    elif _MIN_PLAIN_EXPONENT < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
        e = n - 1
        body = f"{mantissa}e{'+' if e > 0 else '-'}{abs(e)}"
    return sign + body
