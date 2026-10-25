"""Session-wide test rules.

A skip must never look like a pass. While ARBITR_CI=1 (set by
scripts/ci.sh), any skip fails the whole session: a skip inside a test, and a
skip at collection time (module-level ``pytest.importorskip`` or
``pytest.skip(allow_module_level=True)``). Strict xfail is not a skip.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Shared helpers (tests/shellutil.py) import as plain modules.
sys.path.insert(0, str(Path(__file__).parent))

_skipped: set[str] = set()


def _note(report: pytest.TestReport | pytest.CollectReport) -> None:
    if report.skipped and not hasattr(report, "wasxfail"):
        _skipped.add(report.nodeid or "<collection>")


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    _note(report)


def pytest_collectreport(report: pytest.CollectReport) -> None:
    _note(report)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if os.environ.get("ARBITR_CI") != "1":
        return
    if hasattr(session.config, "workerinput"):
        return  # an xdist worker; the controller sees every report and decides
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    # The terminal reporter's stats also hold skips that xdist workers forwarded.
    if reporter is not None:
        for report in reporter.stats.get("skipped", []):
            _note(report)
    if not _skipped:
        return
    if reporter is not None:
        reporter.write_line(
            f"FAIL: {len(_skipped)} skip(s) while ARBITR_CI=1. Skips are failures in CI:",
            red=True,
        )
        for nodeid in sorted(_skipped):
            reporter.write_line(f"  skipped: {nodeid}", red=True)
    if exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
