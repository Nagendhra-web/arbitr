"""Outbound data loss prevention: what an outbound message must not carry.

Deterministic detectors scan the arguments of ``external_comm`` actions:

- **secrets**: the same detectors the ledger uses for redaction (cloud and SaaS
  keys, tokens, private keys, credentials in URLs). Findings are named
  ``secret`` and ``secret:<detector>``.
- **personal data**: email addresses in content (recipient fields are where a
  message goes, not what it carries, so they are skipped), phone numbers in
  phone-like formats, and card numbers that pass the Luhn check. National ID
  formats are plugins, for example :data:`US_SSN`. Findings are ``pii`` and
  ``pii:<detector>``.
- **private content**: text the run read earlier from tools with
  ``private_output``, recognized by fingerprints of 8-word shingles. The
  finding is ``private_content``.

Argument keys and integers (card numbers) are scanned too. Arguments too large
to scan, values of unknown types, and fingerprint sets that filled up give
``unscannable``, so a policy can fail closed.
A finding names the detector and the argument path, never the matched text.

Example:
    >>> sorted(outbound_findings("external_comm", {"body": "card 4111 1111 1111 1111"}))
    ['pii', 'pii:card']
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from arbitr.core.redact import DETECTORS as SECRET_DETECTORS
from arbitr.core.redact import luhn_valid

SHINGLE_WORDS: Final = 8
"""Words per shingle. Shorter runs of copied text are not fingerprinted."""

MIN_SHARED_SHINGLES: Final = 2
"""A message is a copy when it shares this many shingles (9+ words in a row)."""

_MAX_NODES: Final = 10_000
_MAX_TEXT: Final = 1_000_000
_MOD: Final = (1 << 61) - 1
_BASE: Final = 1_000_003
_WORD: Final = re.compile(r"\w+")
_PLAIN_KEY: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_CARD: Final = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
_CARD_DIGITS: Final = range(13, 20)
_EMAIL: Final = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}"
    r"(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)
_PHONE: Final = re.compile(
    r"(?<![\w+])(?:"
    r"\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]\d{2,4}){1,4}"
    r"|\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}"
    r"|\d{3}[.-]\d{3}[.-]\d{4}"
    r")(?![\w-])"
)
_MIN_PHONE_DIGITS: Final = 8
_RECIPIENT_KEYS: Final = frozenset(
    {
        "to",
        "cc",
        "bcc",
        "recipient",
        "recipients",
        "email",
        "emails",
        "to_address",
        "to_addresses",
        "to_email",
        "reply_to",
        "from",
        "sender",
        "from_address",
        "from_email",
    }
)


@dataclass(frozen=True)
class Detector:
    """A personal data detector: a pattern and an optional check on each match."""

    name: str
    pattern: re.Pattern[str]
    check: Callable[[str], bool] | None = None

    def found_in(self, text: str) -> bool:
        """Whether the text holds at least one match that passes the check."""
        return any(
            self.check is None or self.check(m.group(0)) for m in self.pattern.finditer(text)
        )


def _card(match: str) -> bool:
    digits = re.sub(r"\D", "", match)
    return len(digits) in _CARD_DIGITS and luhn_valid(digits)


def _phone(match: str) -> bool:
    return len(re.sub(r"\D", "", match)) >= _MIN_PHONE_DIGITS


PII_DETECTORS: Final = (
    Detector("card", _CARD, _card),
    Detector("phone", _PHONE, _phone),
)

US_SSN: Final = Detector(
    "us_ssn", re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")
)
"""United States Social Security numbers. Opt in through ``extra_detectors``."""


@dataclass(frozen=True)
class Finding:
    """One detector hit: which detector, and where in the arguments."""

    detector: str
    path: str


# ---------------------------------------------------------------- fingerprints


def _word_hash(word: str) -> int:
    return int.from_bytes(hashlib.blake2b(word.encode(), digest_size=8).digest(), "big") % _MOD


def _shingles(text: str) -> Iterable[int]:
    """Rolling polynomial hashes of every window of SHINGLE_WORDS words."""
    words = [_word_hash(w) for w in _WORD.findall(text.lower())]
    if len(words) < SHINGLE_WORDS:
        return
    top = pow(_BASE, SHINGLE_WORDS - 1, _MOD)
    value = 0
    for h in words[:SHINGLE_WORDS]:
        value = (value * _BASE + h) % _MOD
    yield value
    for i in range(SHINGLE_WORDS, len(words)):
        value = ((value - words[i - SHINGLE_WORDS] * top) * _BASE + words[i]) % _MOD
        yield value


class PrivateFingerprints:
    """Shingles of private text a run has read. Kept in memory for the run only.

    The hashes do not depend on ``PYTHONHASHSEED``, so results are the same in
    every process.
    """

    def __init__(self, max_shingles: int = 1_000_000) -> None:
        """Create an empty set that holds at most ``max_shingles`` shingles."""
        self._max = max_shingles
        self._shingles: set[int] = set()
        self._complete = True

    def __len__(self) -> int:
        """The number of shingles held."""
        return len(self._shingles)

    @property
    def complete(self) -> bool:
        """False once something private could not be fingerprinted.

        Then a copy of it would go unseen, so every scan reports
        ``unscannable:private_content`` and a policy can fail closed.
        """
        return self._complete

    def add(self, text: str) -> None:
        """Fingerprint one whole text. Once full, the set is marked incomplete."""
        for value in _shingles(text):
            if value in self._shingles:
                continue
            if len(self._shingles) >= self._max:
                self._complete = False
                return
            self._shingles.add(value)

    def add_value(self, value: object) -> None:
        """Fingerprint every string inside a tool result."""
        try:
            leaves, _ = _leaves(value)
        except _TooLargeError:
            self._complete = False
            return
        for leaf in leaves:
            if isinstance(leaf.value, str):
                self.add(leaf.value)

    def shared(self, text: str) -> int:
        """How many of the text's shingles were read before."""
        return sum(1 for value in set(_shingles(text)) if value in self._shingles)

    def snapshot(self) -> tuple[int, ...]:
        """The shingles, sorted. For tests and debugging."""
        return tuple(sorted(self._shingles))


# ---------------------------------------------------------------- scanning


class _TooLargeError(Exception):
    pass


@dataclass(frozen=True)
class _Leaf:
    path: str
    value: str | int
    recipient: bool = False


def _child_path(path: str, key: object) -> str:
    text = str(key)
    if _PLAIN_KEY.fullmatch(text):
        return f"{path}.{text}"
    return f"{path}[{json.dumps(text)[1:-1]!r}]".replace('"', "'")


def _scalar_leaf(path: str, item: object, recipient: bool) -> list[_Leaf] | None:  # noqa: FBT001
    """Leaves for a scalar (none for booleans and nulls), or None when not a scalar."""
    if isinstance(item, str):
        return [_Leaf(path, item, recipient)]
    if isinstance(item, bool) or item is None:
        return []
    if isinstance(item, int):
        return [_Leaf(path, item)]
    if isinstance(item, float):
        integral = math.isfinite(item) and item.is_integer()
        return [_Leaf(path, int(item))] if integral else []  # 4111111111111111.0 is a card too
    return None


def _leaves(value: object) -> tuple[list[_Leaf], list[str]]:
    """String and integer leaves (keys included) and the paths of unknown types.

    Raises _TooLargeError past the node limit.
    """
    leaves: list[_Leaf] = []
    unknown: list[str] = []
    stack: list[tuple[str, object, bool]] = [("$", value, False)]
    seen = 0
    while stack:
        path, item, recipient = stack.pop()
        seen += 1
        if seen > _MAX_NODES:
            raise _TooLargeError
        scalar = _scalar_leaf(path, item, recipient)
        if scalar is not None:
            leaves.extend(scalar)
        elif isinstance(item, Mapping):
            for key, child in reversed(list(item.items())):
                child_path = _child_path(path, key)
                leaves.append(_Leaf(child_path, str(key)))
                top_recipient = path == "$" and str(key).lower() in _RECIPIENT_KEYS
                stack.append((child_path, child, top_recipient))
        elif isinstance(item, list | tuple):
            stack.extend((f"{path}[{i}]", v, recipient) for i, v in reversed(list(enumerate(item))))
        else:
            unknown.append(path)
    return leaves, unknown


def _scan_leaf(
    leaf: _Leaf,
    detectors: tuple[Detector, ...],
    fingerprints: PrivateFingerprints | None,
) -> list[Finding]:
    path, text = leaf.path, leaf.value
    if isinstance(text, int):
        digits = str(abs(text))
        card = len(digits) in _CARD_DIGITS and luhn_valid(digits)
        return [Finding("pii:card", path)] if card else []
    found: list[Finding] = []
    if len(text) > _MAX_TEXT:
        found.append(Finding("unscannable", path))
        text = text[:_MAX_TEXT]
    found.extend(
        Finding(f"secret:{name}", path)
        for name, pattern in SECRET_DETECTORS
        if pattern.search(text)
    )
    if not leaf.recipient and _EMAIL.search(text):
        found.append(Finding("pii:email", path))
    found.extend(Finding(f"pii:{d.name}", path) for d in detectors if d.found_in(text))
    if fingerprints is not None and fingerprints.shared(text) >= MIN_SHARED_SHINGLES:
        found.append(Finding("private_content", path))
    return found


def scan_outbound(
    args: Mapping[str, object],
    *,
    fingerprints: PrivateFingerprints | None = None,
    extra_detectors: tuple[Detector, ...] = (),
) -> tuple[Finding, ...]:
    """Scan every string in the arguments. Findings are sorted by path, then detector."""
    try:
        leaves, unknown = _leaves(args)
    except _TooLargeError:
        return (Finding("unscannable", "$"),)
    detectors = PII_DETECTORS + extra_detectors
    findings = [f for leaf in leaves for f in _scan_leaf(leaf, detectors, fingerprints)]
    findings.extend(Finding("unscannable", path) for path in unknown)
    if fingerprints is not None and not fingerprints.complete:
        findings.append(Finding("unscannable:private_content", "$"))
    return tuple(sorted(set(findings), key=lambda f: (f.path, f.detector)))


def finding_names(findings: Iterable[Finding]) -> frozenset[str]:
    """Names for rules: every detector and its category (``secret``, ``pii``)."""
    names: set[str] = set()
    for finding in findings:
        names.add(finding.detector)
        names.add(finding.detector.split(":", 1)[0])
    return frozenset(names)


def outbound_findings(
    effect: str,
    args: Mapping[str, object],
    *,
    fingerprints: PrivateFingerprints | None = None,
    extra_detectors: tuple[Detector, ...] = (),
) -> frozenset[str]:
    """Finding names for the gate. Only ``external_comm`` actions are scanned."""
    if effect != "external_comm":
        return frozenset()
    found = scan_outbound(args, fingerprints=fingerprints, extra_detectors=extra_detectors)
    return finding_names(found)
