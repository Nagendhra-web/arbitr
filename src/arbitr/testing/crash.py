"""Crash injection: test that your own tools stay exactly-once when a worker dies.

``crash_at`` makes the next tool call through a ledger stop dead at a chosen
point, as if the process were killed: nothing after that point is recorded.
``restart`` then makes the same ledger behave like a fresh worker that starts
after the dead worker's lease ran out, so the next call with the same
arguments goes through recovery (native tools run again with the same key,
probe tools ask the service, the rest wait for a human).

Example::

    def test_refund_survives_a_crash(arbitr_ledger, arbitr_run):
        with crash_at(arbitr_ledger, "after_tool"), pytest.raises(SimulatedCrash):
            refund("o-1", 25)
        restart(arbitr_ledger)
        refund("o-1", 25)           # recovery: the same refund, not a second one
        assert payments.count() == 1
"""

from __future__ import annotations

import threading
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, Literal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from arbitr.executor import Ledger

__all__ = ["CRASH_POINTS", "SimulatedCrash", "crash_at", "restart"]

CrashPoint = Literal["before_tool", "after_tool"]

CRASH_POINTS: Final[dict[str, str]] = {
    "before_tool": "after_executing_commit",
    "after_tool": "after_side_effect",
}
"""Where a call can die: just before the tool runs (the ledger already said it
would), or just after the tool acted (before the ledger recorded the result)."""


class SimulatedCrash(BaseException):
    """The worker died. A ``BaseException``, so ordinary error handling does not swallow it."""


@contextmanager
def crash_at(ledger: Ledger, point: CrashPoint = "after_tool") -> Iterator[None]:
    """Inside the block, the next tool call through ``ledger`` dies at ``point``.

    Raises:
        ValueError: ``point`` is not one of ``CRASH_POINTS``.
    """
    step = CRASH_POINTS.get(point)
    if step is None:
        raise ValueError(f"crash point must be one of {sorted(CRASH_POINTS)}")
    previous = ledger.on_step
    fired = threading.Event()

    def on_step(name: str) -> None:
        if previous is not None:
            previous(name)
        if name == step and not fired.is_set():
            fired.set()
            raise SimulatedCrash(f"the worker died {point.replace('_', ' ')}")

    ledger.on_step = on_step
    try:
        yield
    finally:
        ledger.on_step = previous


def restart(ledger: Ledger, *, margin: float = 1.0) -> Ledger:
    """Make ``ledger`` act as a new worker that starts after the dead one's lease expired.

    The ledger gets a new worker id, fresh connections, and a clock moved
    ``lease_ttl + margin`` seconds ahead (only for this ledger object). The
    run context of the caller stays as it is, so the same call can be made
    again right away. Returns ``ledger``.
    """
    with ledger._lock:  # the testing kit restarts the ledger in place
        for storage in ledger._opened:
            storage.close()
        ledger._opened.clear()
    ledger._local = threading.local()
    ledger.worker_id = f"restarted-{uuid.uuid4().hex[:8]}"
    skew = timedelta(seconds=ledger.lease_ttl + margin)
    base = ledger.clock

    def later() -> datetime:
        return (base() if base is not None else datetime.now(UTC)) + skew

    ledger.clock = later
    return ledger
