"""Tool-specific previewers used by the preview and executor tests."""

from __future__ import annotations

import threading
from collections.abc import Mapping

from arbitr.preview import Preview

RELEASE = threading.Event()
"""Set by tests to let a slow previewer return."""

CALLS: list[Mapping[str, object]] = []


def big(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
    """Reports many affected rows and a secret-looking fact."""
    CALLS.append(args)
    return Preview(
        "DELETE would remove 5,000 rows from orders",
        {
            "rows_affected": 5000,
            "api_token": "tok-" + "123456789",
        },  # built from pieces for scanners
    )


def slow(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
    """Waits until released (or ten seconds), so a short timeout fires first."""
    RELEASE.wait(10)
    return Preview("late", {"rows_affected": 1})


def broken(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
    """Always fails."""
    raise RuntimeError("previewer bug")


NOT_CALLABLE = 5
