"""Simulation workloads and their invariants.

``CounterWorkload`` is a toy: workers increment a shared counter through
a write-ahead pattern (log the intent, apply, commit) and may crash between any
two steps. A recovery pass on restart finishes logged but uncommitted
increments. The apply step is keyed by operation id, like a native idempotency
key, so the invariant is: every logged increment takes effect exactly once.

It is fast enough to run on every seed. ledger_workload.py runs the real
executor the same way on fewer seeds.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from engine import Simulator, Sleep, Step, WorkerGen

if TYPE_CHECKING:
    from collections.abc import Callable


class InvariantError(AssertionError):
    """An invariant failed on a recorded history."""


class CounterWorkload:
    """Write-ahead counter increments with crash recovery."""

    def __init__(self, sim: Simulator, workers: int = 4, increments: int = 5) -> None:
        self.sim = sim
        self.workers = workers
        self.increments = increments
        self.log: dict[str, str] = {}  # op id -> "pending" | "committed", durable
        self.applied: set[str] = set()  # op ids whose effect happened, durable
        self.counter = 0
        for w in range(workers):
            sim.spawn(f"w{w}", self._factory(w))

    def _factory(self, w: int) -> Callable[[], WorkerGen]:
        return lambda: self._worker(w)

    def _apply(self, op: str) -> None:
        if op not in self.applied:
            self.applied.add(op)
            self.counter += 1
            self.sim.record("effect", op=op)

    def _recover(self, w: int) -> WorkerGen:
        for op, status in sorted(self.log.items()):
            if status == "pending" and op.startswith(f"w{w}-"):
                yield Step(f"recover {op}")
                self._apply(op)
                self.log[op] = "committed"

    def _worker(self, w: int) -> WorkerGen:
        yield from self._recover(w)
        for n in range(self.increments):
            op = f"w{w}-{n}"
            if self.log.get(op) == "committed":
                continue
            self.log[op] = "pending"
            self.sim.record("logged", op=op)
            yield Step(f"after log {op}")
            self._apply(op)
            yield Step(f"after effect {op}")
            self.log[op] = "committed"
            self.sim.record("committed", op=op)
            yield Sleep(self.sim.rng.uniform(0.0, 0.05))

    def check(self) -> None:
        """Check the invariants after ``sim.run()``."""
        expected = self.workers * self.increments
        check_history(self.sim, expected_effects=expected)
        if self.counter != expected:
            raise InvariantError(f"seed {self.sim.seed}: counter {self.counter} != {expected}")
        if any(status != "committed" for status in self.log.values()):
            raise InvariantError(f"seed {self.sim.seed}: an operation never committed")


def check_history(sim: Simulator, expected_effects: int) -> None:
    """Invariants on the recorded history: each effect at most once, all present."""
    effects = [e["op"] for e in sim.history if e["kind"] == "effect"]
    if len(effects) != len(set(effects)):
        raise InvariantError(f"seed {sim.seed}: an effect happened twice")
    if len(effects) != expected_effects:
        raise InvariantError(
            f"seed {sim.seed}: {len(effects)} effects, expected {expected_effects}"
        )
