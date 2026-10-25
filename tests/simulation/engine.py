"""Deterministic simulation engine.

In the style of FoundationDB and TigerBeetle simulation testing: a seeded
scheduler interleaves many virtual workers, a virtual clock replaces wall
time, and a fault plan can crash a worker between any two of its steps. Every
run is a pure function of its seed, so a failing seed replays exactly.

Workers are generators. Each ``yield`` is a step boundary where the scheduler
may switch workers or inject a crash. A worker yields ``Sleep(seconds)`` to
advance its own virtual time, or ``Step(label)`` to mark a boundary.

For now it ships with a toy workload. Later the real ledger and executor plug
in through a fake storage layer that can delay, fail or crash between any two
operations, and the protocol invariants are checked on the recorded history.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import random
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Sleep:
    """Advance this worker's virtual time."""

    seconds: float


@dataclass(frozen=True)
class Step:
    """Mark a step boundary where the scheduler may switch or crash."""

    label: str


Action = Sleep | Step
WorkerGen = Generator[Action, None, None]


class VirtualClock:
    """A clock that only moves when the simulator says so."""

    def __init__(self) -> None:
        self.now = 0.0

    def advance_to(self, t: float) -> None:
        if t < self.now:
            raise ValueError("virtual time cannot go backwards")
        self.now = t


@dataclass
class FaultPlan:
    """Probability of crashing a worker at each step boundary."""

    crash_probability: float = 0.0
    max_crashes: int = 0


@dataclass(order=True)
class _Ready:
    at: float
    seq: int
    name: str = field(compare=False)


class Simulator:
    """Run workers under a seeded scheduler and record a history."""

    def __init__(self, seed: int, faults: FaultPlan | None = None) -> None:
        self.seed = seed
        self.rng = random.Random(seed)  # noqa: S311, determinism, not security
        self.clock = VirtualClock()
        self.faults = faults or FaultPlan()
        self.history: list[dict[str, Any]] = []
        self.crashes = 0
        self._workers: dict[str, WorkerGen] = {}
        self._factories: dict[str, Callable[[], WorkerGen]] = {}
        self._queue: list[_Ready] = []
        self._seq = 0

    def record(self, kind: str, **data: Any) -> None:
        """Append an event to the history at the current virtual time."""
        self.history.append({"t": round(self.clock.now, 9), "kind": kind, **data})

    def spawn(self, name: str, factory: Callable[[], WorkerGen]) -> None:
        """Start a worker. ``factory`` is called again if the worker restarts."""
        self._factories[name] = factory
        self._workers[name] = factory()
        self._schedule(name, self.clock.now)

    def _schedule(self, name: str, at: float) -> None:
        self._seq += 1
        # Random jitter breaks ties between workers ready at the same time.
        jitter = self.rng.random() * 1e-6
        heapq.heappush(self._queue, _Ready(at + jitter, self._seq, name))

    def _maybe_crash(self, name: str) -> bool:
        f = self.faults
        if self.crashes >= f.max_crashes or self.rng.random() >= f.crash_probability:
            return False
        self.crashes += 1
        self._workers[name].close()
        self.record("crash", worker=name)
        # A crashed worker restarts after a random delay, like a process supervisor.
        self._workers[name] = self._factories[name]()
        self._schedule(name, self.clock.now + self.rng.uniform(0.01, 1.0))
        return True

    def run(self, max_steps: int = 100_000) -> None:
        """Run until every worker finishes or ``max_steps`` is reached."""
        steps = 0
        while self._queue:
            steps += 1
            if steps > max_steps:
                raise RuntimeError(f"seed {self.seed}: no progress after {max_steps} steps")
            ready = heapq.heappop(self._queue)
            self.clock.advance_to(max(self.clock.now, ready.at))
            if self._maybe_crash(ready.name):
                continue
            try:
                action = next(self._workers[ready.name])
            except StopIteration:
                self.record("done", worker=ready.name)
                continue
            delay = action.seconds if isinstance(action, Sleep) else 0.0
            self._schedule(ready.name, self.clock.now + delay)

    def history_digest(self) -> str:
        """Return a stable hash of the history, used to prove determinism."""
        blob = json.dumps(self.history, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()
