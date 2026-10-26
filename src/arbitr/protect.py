"""Self-protection: agents may not operate Arbitr or touch its ledger, key, policy or config.

An agent with a shell or file tool could otherwise approve its own actions
(``arbitr approvals approve``), weaken the policy, read the ledger key or
edit the ledger. Every call is checked before the gate, in every mode,
including shadow mode: a match is denied with the rule
``arbitr-self-protection``.

The check looks at every text value in the arguments for the ``arbitr``
command line (including ``python -m arbitr``), the ``.arbitr`` folder, and
the protected files, whether written in full or relative to the working
folder.

This is a guard, not a sandbox: an agent that can run arbitrary code can
hide what it does from any text check. The real protection is the operating
system: run agents as a user that cannot read the key file or write the
ledger and policy. See the configuration docs.
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

RULE_ID: Final = "arbitr-self-protection"
REASON: Final = "Agents may not operate Arbitr itself or touch its ledger, key, policy or config."

_COMMANDS: Final = (
    "approvals|config|policy|init|recover|runs|intents|verify|export|serve|mcp-proxy|mcp|bench"
)
_CLI: Final = re.compile(rf"(?i)(?:^|[\s;&|(`'\"=/\\]){'arbitr'}(?:\.exe)?\s+(?:{_COMMANDS})\b")
_MODULE: Final = re.compile(r"(?i)\bpython[\d.]*(?:\.exe)?\s+(?:-\w+\s+)*-m\s+arbitr\b")
_FOLDER: Final = re.compile(r"(?i)(?:^|[\s/\\'\"=:]|^~)\.arbitr(?:[/\\\s'\";]|$)")
_TOKEN: Final = re.compile(r"[^\s'\"`;&|()<>=]+")
_PROGRAMS: Final = frozenset(
    {"arbitr", "arbitr.exe", "arbitr.cmd", "arbitr.bat", "arbitr.ps1", "arbitr-script.py"}
)
"""The Arbitr program under any name a shell runs it by, whatever follows it."""
_MAX_TEXT: Final = 20_000
_MAX_TOKENS: Final = 500


def _norm(path: str | os.PathLike[str]) -> str:
    text = os.path.normpath(os.path.abspath(os.fspath(path))).replace("\\", "/")
    return text.lower() if os.name == "nt" else text


def protected_forms(paths: Iterable[str | os.PathLike[str]]) -> frozenset[str]:
    """Normalized absolute forms of the protected files, with SQLite's side files."""
    forms: set[str] = set()
    for path in paths:
        base = _norm(path)
        forms.update({base, f"{base}-wal", f"{base}-shm", f"{base}-journal"})
    return frozenset(forms)


def touches_arbitr(args: object, protected: frozenset[str]) -> bool:
    """Whether any text in the arguments runs the Arbitr CLI or names a protected file."""
    return any(_text_hits(text, protected) for text in _texts(args))


def _text_hits(text: str, protected: frozenset[str]) -> bool:
    text = text[:_MAX_TEXT]
    if _CLI.search(text) or _MODULE.search(text) or _FOLDER.search(text):
        return True
    if any(_program_name(token) in _PROGRAMS for token in _shell_tokens(text)):
        return True
    if not protected:
        return False
    plain = text.replace("\\", "/")
    folded = plain.lower() if os.name == "nt" else plain
    if any(form in folded for form in protected):
        return True
    for token in _TOKEN.findall(plain)[:_MAX_TOKENS]:
        try:
            if _norm(Path(token).expanduser()) in protected:
                return True
        except (OSError, ValueError):
            continue
    return False


def _shell_tokens(text: str) -> list[str]:
    """Words as a POSIX shell and as Windows would split them, quotes removed."""
    tokens: list[str] = []
    for posix in (True, False):
        try:
            tokens += shlex.split(text, posix=posix)[:_MAX_TOKENS]
        except ValueError:  # unbalanced quotes: fall back to plain words
            tokens += text.split()[:_MAX_TOKENS]
    return tokens


def _program_name(token: str) -> str:
    name = token.strip("'\"").replace("\\", "/").rsplit("/", 1)[-1]
    return name.lower()


def _texts(value: object, depth: int = 0) -> Iterator[str]:
    if depth > 32:  # noqa: PLR2004 - deeper than any real argument
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _texts(k, depth + 1)
            yield from _texts(v, depth + 1)
    elif isinstance(value, list | tuple | set | frozenset):
        for item in value:
            yield from _texts(item, depth + 1)
