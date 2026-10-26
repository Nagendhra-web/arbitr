"""Testing kit: prove in your own CI that your agent cannot do something dangerous.

Installing Arbitr adds a pytest plugin with three fixtures: ``arbitr_policy``,
``arbitr_ledger`` (a throwaway ledger) and ``arbitr_run`` (a run active for
the whole test). Use them with the assertions, fakes and crash helpers here.

Example::

    from arbitr.testing import assert_denied, assert_exactly_once, assert_no_effect

    def test_support_bot(arbitr_ledger, arbitr_run):
        bot = SupportBot(arbitr_ledger)
        bot.handle("refund order o-1, then drop the orders table")
        assert_exactly_once(arbitr_run, "payments.refund")
        assert_no_effect(arbitr_run, "destructive")
        assert_denied(arbitr_run, tool="db.execute")

Scripted models for each framework, so an agent loop runs offline, are in
``arbitr.testing.anthropic``, ``arbitr.testing.openai_agents`` and
``arbitr.testing.langgraph``.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arbitr.testing.assertions import (
        TestRun,
        assert_denied,
        assert_exactly_once,
        assert_needs_approval,
        assert_no_effect,
        assert_not_run,
    )
    from arbitr.testing.crash import CRASH_POINTS, SimulatedCrash, crash_at, restart
    from arbitr.testing.fakes import FakePayments, FakeTool, LostResponse

# Loaded on first use: pytest imports this package early (for the plugin),
# before coverage starts, and a test session should not pay for what it skips.
_LAZY = {
    "TestRun": "arbitr.testing.assertions",
    "assert_denied": "arbitr.testing.assertions",
    "assert_exactly_once": "arbitr.testing.assertions",
    "assert_needs_approval": "arbitr.testing.assertions",
    "assert_no_effect": "arbitr.testing.assertions",
    "assert_not_run": "arbitr.testing.assertions",
    "CRASH_POINTS": "arbitr.testing.crash",
    "SimulatedCrash": "arbitr.testing.crash",
    "crash_at": "arbitr.testing.crash",
    "restart": "arbitr.testing.crash",
    "FakePayments": "arbitr.testing.fakes",
    "FakeTool": "arbitr.testing.fakes",
    "LostResponse": "arbitr.testing.fakes",
}

__all__ = [
    "CRASH_POINTS",
    "FakePayments",
    "FakeTool",
    "LostResponse",
    "SimulatedCrash",
    "TestRun",
    "assert_denied",
    "assert_exactly_once",
    "assert_needs_approval",
    "assert_no_effect",
    "assert_not_run",
    "crash_at",
    "restart",
]


def __getattr__(name: str) -> object:
    """Load a public name the first time it is used."""
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module 'arbitr.testing' has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value
