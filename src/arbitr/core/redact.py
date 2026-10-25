"""Redaction: secrets never reach storage, logs or exports in clear.

Two things are redacted before anything is stored:

1. Fields named by a tool's ``ToolSpec.redact`` JSON paths.
2. Anything in any string that looks like a secret: private keys, cloud and SaaS
   API keys, bearer tokens, JWTs, ``password=...`` style assignments, and
   card-like digit runs that pass the Luhn check.

A redacted value becomes ``<redacted:hmac-sha256:...>``. The marker is a keyed
HMAC, not a plain hash, so a short secret such as a card number cannot be
recovered by hashing every candidate. Equal values give equal markers under
the same key, so stored records can still be compared.

Hashes used for identity (intent hash, idempotency key) are computed from the
full values in memory, before redaction, and are not affected.

Limit, stated plainly: a secret with no recognizable shape and no label, such
as a bare password inside a sentence, cannot be detected. Put secrets in named
fields (``password``, ``token``, ...) or list them in ``ToolSpec.redact``.

Example:
    >>> r = Redactor(b"k" * 32)
    >>> out = r.redact({"user": "ann", "note": "key sk-ant-api03-abcdefghijklmnopqrstuv"})
    >>> out["user"], "sk-ant" in str(out)
    ('ann', False)
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from typing import Final

from arbitr.core.canonical import canonicalize
from arbitr.policy import jsonpath

MARKER_PREFIX: Final = "<redacted:hmac-sha256:"
MIN_KEY_BYTES: Final = 32

_CARD_MIN_DIGITS: Final = 13
_CARD_MAX_DIGITS: Final = 19

DETECTORS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
            re.S,
        ),
    ),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})"),
    ),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("basic_auth", re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/]{8,}={0,2}")),
    # user:password@host in any URL; only the password is replaced.
    ("url_credentials", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s@]+)@")),
    (
        "assigned_secret",
        # Also matches JSON and quoted forms such as "password": "...".
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|client[_-]?secret|private[_-]?key"
            r"|api[_-]?key|access[_-]?token|auth[_-]?token)"
            r"[\"']?\s*[:=]\s*[\"']?([^\s\"',;}]{6,})"
        ),
    ),
)

SENSITIVE_KEYS: Final = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pw",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "client_secret",
        "authorization",
        "cookie",
        "set_cookie",
        "secret_key",
        "passphrase",
        "credentials",
    }
)
"""Object keys whose whole value is always redacted.

Matching ignores case and spelling style: ``accessToken``, ``AccessToken``,
``access-token`` and ``access_token`` are the same name.
"""

SENSITIVE_SUFFIXES: Final = (
    "_password",
    "_passwd",
    "_secret",
    "_token",
    "_api_key",
    "_apikey",
    "_access_key",
    "_private_key",
    "_secret_key",
    "_passphrase",
    "_credentials",
    "_authorization",
    "_cookie",
)

# Word boundaries inside camelCase and PascalCase names: dbPassword, DBPassword.
_CAMEL_BOUNDARY: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def is_sensitive_key(key: str) -> bool:
    """Return whether a field name marks its value as a secret.

    Example:
        >>> is_sensitive_key("DB-Password"), is_sensitive_key("clientSecret")
        (True, True)
        >>> is_sensitive_key("tokenizer"), is_sensitive_key("idempotencyKey")
        (False, False)
    """
    name = _CAMEL_BOUNDARY.sub("_", key).lower().replace("-", "_")
    return name in SENSITIVE_KEYS or name.endswith(SENSITIVE_SUFFIXES)


_CARD = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
_MARKER = re.compile(re.escape(MARKER_PREFIX) + r"[0-9a-f]{64}>")


def luhn_valid(digits: str) -> bool:
    """Return whether a digit string passes the Luhn checksum.

    Example:
        >>> luhn_valid("4111111111111111"), luhn_valid("4111111111111112")
        (True, False)
    """
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2  # noqa: PLR2004, Luhn doubles digits above 4
        total += d
    return total % 10 == 0


class Redactor:
    """Replace secrets with keyed markers.

    ``key`` must be at least 32 bytes. It comes from configuration, never from
    the database, so someone who can read the database cannot test guesses.
    """

    def __init__(self, key: bytes, *, detect: bool = True) -> None:
        """Create a redactor with an HMAC key of at least 32 bytes."""
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"redaction key must be at least {MIN_KEY_BYTES} bytes")
        self._key = key
        self.detect = detect

    def marker(self, value: object) -> str:
        """Return the marker that stands in for ``value``.

        Example:
            >>> Redactor(b"k" * 32).marker("x").startswith("<redacted:hmac-sha256:")
            True
        """
        digest = hmac.new(self._key, canonicalize(value), hashlib.sha256).hexdigest()
        return f"{MARKER_PREFIX}{digest}>"

    def redact(self, value: object, paths: Iterable[str] = ()) -> object:
        """Return a redacted copy of ``value``. The input is never modified.

        Fields matching ``paths`` are replaced whole; then, if detection is on,
        secret-looking text inside every remaining string is replaced.
        """
        result = value
        for path in paths:
            result = jsonpath.replace(result, path, self.marker)
        if self.detect:
            result = self._scrub(result)
        return result

    def redact_text(self, text: str) -> str:
        """Replace every secret-looking span in ``text`` with its marker.

        Example:
            >>> r = Redactor(b"k" * 32)
            >>> r.redact_text("card 4111 1111 1111 1111 ok").startswith("card <redacted")
            True
        """
        # Complete markers already in the text are kept; everything around them is scanned.
        pieces = _MARKER.split(text)
        markers = _MARKER.findall(text)
        out = [self._scan(pieces[0])]
        for marker, piece in zip(markers, pieces[1:], strict=True):
            out.append(marker)
            out.append(self._scan(piece))
        return "".join(out)

    def _scan(self, text: str) -> str:
        for _name, pattern in DETECTORS:
            text = pattern.sub(self._replace_match, text)
        return _CARD.sub(self._replace_card, text)

    def _replace_match(self, match: re.Match[str]) -> str:
        if match.lastindex:  # redact only the captured secret, keep the label
            start, end = match.span(1)
            whole_start = match.start()
            return (
                match.group(0)[: start - whole_start]
                + self.marker(match.group(1))
                + match.group(0)[end - whole_start :]
            )
        return self.marker(match.group(0))

    def _replace_card(self, match: re.Match[str]) -> str:
        digits = re.sub(r"[ -]", "", match.group(0))
        if _CARD_MIN_DIGITS <= len(digits) <= _CARD_MAX_DIGITS and luhn_valid(digits):
            return self.marker(digits)
        return match.group(0)

    def _scrub(self, value: object) -> object:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, Mapping):
            out: dict[object, object] = {}
            for k, v in value.items():
                if isinstance(k, str) and is_sensitive_key(k):
                    out[k] = self.marker(v)  # the whole value, whatever its type
                else:
                    # Keys are scanned too: a secret used as a key must not reach storage.
                    out[self.redact_text(k) if isinstance(k, str) else k] = self._scrub(v)
            return out
        if isinstance(value, list | tuple):
            return [self._scrub(v) for v in value]
        if isinstance(value, int) and not isinstance(value, bool):
            digits = str(abs(int.__index__(value)))
            if _CARD_MIN_DIGITS <= len(digits) <= _CARD_MAX_DIGITS and luhn_valid(digits):
                return self.marker(digits)
        return value
