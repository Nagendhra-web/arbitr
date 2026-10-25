r"""Regular expressions in policy rules, on a linear-time engine.

Rules match agent-controlled text, so a backtracking engine would let a
crafted argument stall the gate (``.*a.*b.*c`` takes seconds on a few hundred
characters in Python's ``re``). Policy regexes run on RE2 instead, which
matches in time linear in the input for every pattern it accepts.

RE2 has no lookaround and no backreferences, and it spells the absolute end of
the text ``\z`` (Python's ``\Z``). Patterns that use those are refused when
the policy loads.

Two differences from Python's ``re`` would let text slip past a deny rule, so
``search_rule`` evens them out:

- RE2's ``$`` matches only at the very end, while Python's also matches before
  a final newline. Text that ends in a newline is also tried without it.
- RE2's ``\s`` is ASCII only. Unicode spaces (no-break space, line separator
  and the rest of Python's ``\s``) are turned into plain spaces first.

Lone surrogates, which RE2 cannot encode, are replaced with U+FFFD. RE2's
``\d``, ``\w`` and ``\b`` are ASCII only too; write ``\pN`` and ``\pL`` for
Unicode digits and letters.

Example:
    >>> search_rule(r"(?i)^drop\s+table$", "DROP" + chr(0xA0) + "TABLE" + chr(10))
    True
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Final

import re2  # type: ignore[import-untyped]

MAX_REGEX_LENGTH: Final = 256

_OPTIONS: Final = re2.Options()
_OPTIONS.log_errors = False  # errors are reported through PolicyError, not stderr

# Every character Python's \s matches beyond RE2's [\t\n\f\r ].
_UNICODE_SPACES: Final = (
    0x0B, 0x1C, 0x1D, 0x1E, 0x1F, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B),
    0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
)  # fmt: skip
_TO_SPACE: Final = {
    **dict.fromkeys(_UNICODE_SPACES, " "),
    **dict.fromkeys(range(0xD800, 0xE000), "�"),  # lone surrogates
}


@lru_cache(maxsize=512)
def compile_rule_regex(pattern: str) -> Any:  # noqa: ANN401 - re2 ships no type hints
    """Compile a policy regex with RE2.

    Raises:
        ValueError: the pattern is too long or uses syntax RE2 does not support.
    """
    if len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError(f"regex is longer than {MAX_REGEX_LENGTH} characters")
    try:
        return re2.compile(pattern, _OPTIONS)
    except re2.error as exc:
        raise ValueError(
            "regex uses syntax the linear-time engine does not support (lookaround,"
            " backreferences, or \\Z: write \\z for the end of the text)"
        ) from exc


def search_rule(pattern: str, text: str) -> bool:
    r"""Whether a policy regex matches anywhere in ``text``, with Python's ``$`` and ``\s``."""
    regex = compile_rule_regex(pattern)
    prepared = text.translate(_TO_SPACE)
    if regex.search(prepared) is not None:
        return True
    return prepared.endswith("\n") and regex.search(prepared[:-1]) is not None
