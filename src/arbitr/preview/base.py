"""The preview type and the runner that keeps previews safe to call.

A previewer is a callable ``(args, context) -> Preview``. It measures what an
action would affect without changing anything: rows a ``DELETE`` matches,
files under a folder, recipients of an email. ``run_preview`` calls it in a
worker thread, so a slow or broken previewer can never block or crash the
caller: it gets a ``Preview`` with ``ok=False`` instead.

The context a previewer receives is the ledger's preview context plus
``deadline``, a ``time.monotonic()`` value. Previewers that loop (walking a
folder tree, running a query) should stop once it has passed.

Example:
    >>> run_preview(lambda args, ctx: Preview("2 rows", {"rows": 2}), {}, {}, 1.0).facts["rows"]
    2
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, TypeAlias

FactValue: TypeAlias = int | float | str
Previewer: TypeAlias = Callable[[Mapping[str, object], Mapping[str, object]], "Preview"]

DEADLINE: Final = "deadline"
"""Context key holding the ``time.monotonic()`` value a previewer should stop by."""

_MAX_SUMMARY: Final = 500
_MAX_ERROR: Final = 300


def _check_facts(facts: Mapping[str, FactValue]) -> dict[str, FactValue]:
    checked: dict[str, FactValue] = {}
    for key, value in dict(facts).items():
        if not isinstance(key, str):
            raise TypeError("preview fact names must be strings")
        if isinstance(value, bool) or not isinstance(value, int | float | str):
            raise TypeError(f"preview fact {key!r} must be an int, a float or a string")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"preview fact {key!r} must be a finite number")
        checked[key] = value
    return checked


@dataclass(frozen=True)
class Preview:
    """What an action would affect, measured before it runs.

    ``summary`` is one plain-English line for a human approver. ``facts`` are
    numbers and short strings that policy rules can test (``rows_affected``,
    ``files``, ``external_recipients``). ``ok`` is False when the preview
    timed out or failed; its facts are then incomplete and must not be trusted.

    Example:
        >>> Preview("DELETE would remove 3 rows from orders", {"rows_affected": 3}).ok
        True
    """

    summary: str
    facts: Mapping[str, FactValue] = field(default_factory=dict)
    ok: bool = True
    error: str | None = None

    def __post_init__(self) -> None:
        """Keep the summary on one short line and freeze a checked copy of the facts."""
        if not isinstance(self.summary, str):
            raise TypeError("a preview summary must be a string")
        object.__setattr__(self, "summary", " ".join(self.summary.split())[:_MAX_SUMMARY])
        object.__setattr__(self, "facts", MappingProxyType(_check_facts(self.facts)))

    @classmethod
    def failed(
        cls, summary: str, *, error: str | None = None, facts: Mapping[str, FactValue] | None = None
    ) -> Preview:
        """A preview that could not be completed. ``facts`` may hold partial counts."""
        return cls(summary, facts or {}, ok=False, error=error)

    def to_record(self) -> dict[str, object]:
        """The preview as plain JSON data, for the audit chain."""
        return {"summary": self.summary, "facts": dict(self.facts), "ok": self.ok,
                "error": self.error}  # fmt: skip

    @classmethod
    def from_record(cls, record: Mapping[str, object]) -> Preview:
        """Rebuild a stored preview. Facts that redaction changed into other shapes are dropped."""
        raw = record.get("facts")
        facts: dict[str, FactValue] = {}
        if isinstance(raw, Mapping):
            for key, value in raw.items():
                if isinstance(value, int | float | str) and not isinstance(value, bool):
                    facts[str(key)] = value
        error = record.get("error")
        return cls(
            str(record.get("summary", "")),
            facts,
            ok=record.get("ok") is True,
            error=None if error is None else str(error),
        )


def deadline_passed(context: Mapping[str, object]) -> bool:
    """Whether the deadline in a previewer's context has passed (False when there is none)."""
    deadline = context.get(DEADLINE)
    if isinstance(deadline, bool) or not isinstance(deadline, int | float):
        return False
    return time.monotonic() >= deadline


def _describe(exc: BaseException) -> str:
    """Only the error's type: its text can carry data the previewer read."""
    return type(exc).__name__[:_MAX_ERROR]


def _call(previewer: Previewer, args: Mapping[str, object], context: Mapping[str, object],
          box: list[Preview]) -> None:  # fmt: skip
    try:
        result = _checked(previewer(args, context))
    except BaseException as exc:  # noqa: BLE001 - a previewer must never crash its caller
        result = Preview.failed(f"Preview failed: {type(exc).__name__}", error=_describe(exc))
    box.append(result)


def _checked(result: object) -> Preview:
    """The previewer's result, or a failed preview when it returned something else."""
    if isinstance(result, Preview):
        return result
    return Preview.failed("Preview failed: the previewer did not return a Preview")


def run_preview(
    previewer: Previewer,
    args: Mapping[str, object],
    context: Mapping[str, object],
    timeout_s: float = 2.0,
) -> Preview:
    """Run a previewer with a time limit. Never raises.

    The previewer runs in a daemon thread. When it does not answer within
    ``timeout_s`` seconds the result is a failed preview saying so; the thread
    is left to finish (previewers should watch the ``deadline`` in their
    context and stop early).

    Example:
        >>> run_preview(lambda a, c: Preview("x"), {}, {}, 0).summary
        'Preview timeout must be a positive number of seconds'
    """
    if not (isinstance(timeout_s, int | float) and math.isfinite(timeout_s) and timeout_s > 0):
        return Preview.failed("Preview timeout must be a positive number of seconds")
    try:
        call_context = {**context, DEADLINE: time.monotonic() + timeout_s}
    except TypeError as exc:
        return Preview.failed("Preview failed: the preview context is not a mapping",
                              error=_describe(exc))  # fmt: skip
    box: list[Preview] = []
    worker = threading.Thread(
        target=_call, args=(previewer, args, call_context, box), name="arbitr-preview", daemon=True
    )
    worker.start()
    worker.join(timeout_s)
    if box:
        return box[0]
    return Preview.failed(f"Preview timed out after {timeout_s:g}s", error="timeout")


def plural(count: int, word: str) -> str:
    """``1 row``, ``48,212 rows``.

    Example:
        >>> plural(2340, "file")
        '2,340 files'
    """
    return f"{count:,} {word}" + ("" if count == 1 else "s")


def format_bytes(size: int) -> str:
    """A byte count in decimal units: ``999 B``, ``1.5 KB``, ``12.0 MB``.

    Example:
        >>> format_bytes(2_500_000)
        '2.5 MB'
    """
    if size < 1000:  # noqa: PLR2004 - the first decimal unit
        return f"{size} B"
    value = float(size)
    for unit in ("KB", "MB", "GB"):
        value /= 1000
        if value < 1000:  # noqa: PLR2004 - the next decimal unit
            return f"{value:.1f} {unit}"
    return f"{value / 1000:.1f} TB"
