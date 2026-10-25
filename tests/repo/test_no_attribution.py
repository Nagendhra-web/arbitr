"""No AI attribution in tracked files.

Commit messages are checked by the commit-msg hook and by `make ci`. This test
covers the tree itself: code comments, docs, changelog, templates.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Built from pieces so this file does not match itself.
PATTERNS = [
    re.compile(r"(?im)^\s*" + "co-authored" + r"-by:\s*\S"),
    re.compile(r"(?i)" + "generated" + r" with \[?claude"),
    re.compile(r"(?i)noreply@" + "anthropic" + r"\.com"),
    re.compile(r"(?i)claude\.(ai|com)/(code/session|share|chat)"),
]

# Files that state the rule itself, so they necessarily quote the patterns.
ALLOWED = {
    "scripts/check_commit_msg.sh",
    "tests/repo/test_no_attribution.py",
}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def test_no_attribution_in_tracked_files() -> None:
    offenders = []
    for rel in tracked_files():
        if rel in ALLOWED:
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        offenders.extend(f"{rel}: {p.pattern}" for p in PATTERNS if p.search(text))
    assert offenders == []


@pytest.mark.parametrize(
    "line",
    [
        "Co-" + "Authored-By: Someone <x@example.com>",
        "\U0001f916 " + "Generated" + " with [Claude Code](https://claude.com/claude-code)",
        "contact noreply@" + "anthropic.com",
    ],
)
def test_patterns_match_real_attribution(line: str) -> None:
    assert any(p.search(line) for p in PATTERNS)
