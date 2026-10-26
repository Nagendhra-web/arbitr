"""The Preview type and run_preview: never raises, always answers in time."""

from __future__ import annotations

import math
import threading
import time
from typing import TYPE_CHECKING

import pytest

from arbitr.preview import DEADLINE, Preview, deadline_passed, run_preview
from arbitr.preview.base import format_bytes, plural

if TYPE_CHECKING:
    from collections.abc import Mapping


def test_preview_keeps_one_line_and_freezes_facts() -> None:
    preview = Preview("DELETE would\nremove  5 rows", {"rows_affected": 5, "table": "t"})
    assert preview.summary == "DELETE would remove 5 rows"
    assert preview.ok
    assert preview.error is None
    assert preview.facts == {"rows_affected": 5, "table": "t"}
    with pytest.raises(TypeError):
        preview.facts["rows_affected"] = 6  # type: ignore[index]


def test_preview_cuts_long_summaries() -> None:
    assert len(Preview("x" * 2000).summary) == 500


@pytest.mark.parametrize(
    "facts",
    [{"flag": True}, {"bad": [1]}, {"nan": math.nan}, {5: 1}, {"inf": math.inf}],
)
def test_preview_refuses_facts_that_are_not_numbers_or_text(facts: dict[object, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        Preview("s", facts)  # type: ignore[arg-type]


def test_preview_refuses_a_summary_that_is_not_text() -> None:
    with pytest.raises(TypeError):
        Preview(5)  # type: ignore[arg-type]


def test_failed_preview_and_record_round_trip() -> None:
    failed = Preview.failed("Preview failed", error="boom", facts={"files": 3})
    assert not failed.ok
    record = failed.to_record()
    assert record == {"summary": "Preview failed", "facts": {"files": 3}, "ok": False,
                      "error": "boom"}  # fmt: skip
    assert Preview.from_record(record) == failed


def test_from_record_tolerates_damaged_records() -> None:
    restored = Preview.from_record({"summary": 5, "facts": {"a": [1], "b": 2}, "ok": "yes"})
    assert restored.summary == "5"
    assert restored.facts == {"b": 2}
    assert not restored.ok
    assert Preview.from_record({"summary": "s", "facts": [], "ok": True}).facts == {}


def test_run_preview_returns_the_previewer_result_and_passes_a_deadline() -> None:
    seen: dict[str, object] = {}

    def previewer(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
        seen.update(context)
        return Preview("ok", {"n": len(args)})

    result = run_preview(previewer, {"a": 1}, {"k": "v"}, 1.0)
    assert result == Preview("ok", {"n": 1})
    assert seen["k"] == "v"
    assert isinstance(seen[DEADLINE], float)


def test_run_preview_turns_errors_into_failed_previews() -> None:
    def broken(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
        raise RuntimeError("database is down")

    result = run_preview(broken, {}, {}, 1.0)
    assert not result.ok
    assert result.summary == "Preview failed: RuntimeError"
    assert result.error == "RuntimeError"  # only the type: the text can carry data


def test_run_preview_refuses_results_that_are_not_previews() -> None:
    result = run_preview(lambda a, c: 5, {}, {}, 1.0)  # type: ignore[arg-type,return-value]
    assert not result.ok
    assert "did not return a Preview" in result.summary


def test_run_preview_times_out() -> None:
    release = threading.Event()

    def slow(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
        release.wait(10)
        return Preview("late")

    started = time.monotonic()
    try:
        result = run_preview(slow, {}, {}, 0.05)
    finally:
        release.set()
    assert time.monotonic() - started < 5
    assert not result.ok
    assert result.summary == "Preview timed out after 0.05s"
    assert result.error == "timeout"


@pytest.mark.parametrize("timeout", [0, -1, math.nan, math.inf])
def test_run_preview_refuses_bad_timeouts(timeout: float) -> None:
    result = run_preview(lambda a, c: Preview("x"), {}, {}, timeout)
    assert not result.ok
    assert "timeout" in result.summary


def test_run_preview_handles_a_context_that_is_not_a_mapping() -> None:
    result = run_preview(lambda a, c: Preview("x"), {}, 5, 1.0)  # type: ignore[arg-type]
    assert not result.ok


def test_deadline_passed() -> None:
    assert not deadline_passed({})
    assert not deadline_passed({DEADLINE: "soon"})
    assert deadline_passed({DEADLINE: time.monotonic() - 1})
    assert not deadline_passed({DEADLINE: time.monotonic() + 60})


def test_formatting_helpers() -> None:
    assert plural(1, "row") == "1 row"
    assert plural(48212, "row") == "48,212 rows"
    assert format_bytes(999) == "999 B"
    assert format_bytes(1500) == "1.5 KB"
    assert format_bytes(12_000_000) == "12.0 MB"
    assert format_bytes(3 * 10**12) == "3.0 TB"
