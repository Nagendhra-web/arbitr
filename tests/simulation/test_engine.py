"""Tests for the simulation engine itself: determinism, faults and the checker."""

from __future__ import annotations

import pytest
from engine import FaultPlan, Simulator, Sleep, Step, WorkerGen
from run import regression_seeds, run_seed
from workloads import CounterWorkload, InvariantError, check_history


def test_same_seed_same_history() -> None:
    assert run_seed(42) == run_seed(42)


def test_different_seeds_differ() -> None:
    assert len({run_seed(s) for s in range(20)}) > 1


def test_crashes_are_injected_and_survived() -> None:
    crashed = 0
    for seed in range(200):
        sim = Simulator(seed, FaultPlan(crash_probability=0.2, max_crashes=5))
        workload = CounterWorkload(sim)
        sim.run()
        workload.check()
        crashed += sim.crashes
    assert crashed > 0


def test_checker_catches_a_double_effect() -> None:
    """Fault injection must expose a workload that applies without idempotency."""
    caught = 0
    for seed in range(50):
        sim = Simulator(seed, FaultPlan(crash_probability=0.5, max_crashes=3))

        def naive(sim: Simulator = sim) -> WorkerGen:
            sim.record("effect", op="x")
            yield Step("after effect")

        sim.spawn("w0", naive)
        sim.run()
        effects = [e for e in sim.history if e["kind"] == "effect"]
        if len(effects) > 1:
            with pytest.raises(InvariantError, match="twice"):
                check_history(sim, expected_effects=1)
            caught += 1
    assert caught > 0


def test_checker_catches_a_lost_effect() -> None:
    sim = Simulator(1)
    with pytest.raises(InvariantError, match="expected 1"):
        check_history(sim, expected_effects=1)


def test_virtual_time_advances_only_by_sleeps() -> None:
    sim = Simulator(1)

    def sleeper() -> WorkerGen:
        yield Sleep(2.5)
        yield Step("woke")

    sim.spawn("s", sleeper)
    sim.run()
    assert 2.5 <= sim.clock.now < 2.6


def test_clock_never_goes_backwards() -> None:
    sim = Simulator(1)
    sim.clock.advance_to(5.0)
    with pytest.raises(ValueError, match="backwards"):
        sim.clock.advance_to(4.0)


def test_no_progress_is_reported() -> None:
    sim = Simulator(3)

    def forever() -> WorkerGen:
        while True:
            yield Step("spin")

    sim.spawn("f", forever)
    with pytest.raises(RuntimeError, match="no progress"):
        sim.run(max_steps=100)


def test_regression_seeds_parse() -> None:
    assert all(isinstance(s, int) for s in regression_seeds())


def test_any_failure_names_its_seed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A failing seed is printed with its replay command, whatever the error."""
    import run  # noqa: PLC0415

    def boom(seed: int, *, verbose: bool = False) -> str:
        raise ValueError(f"unexpected bug at seed {seed}")

    monkeypatch.setattr(run, "run_seed", boom)
    monkeypatch.setattr("sys.argv", ["run.py", "--seed", "77"])
    assert run.main() == 1
    out = capsys.readouterr().out
    assert "FAILED seed 77: ValueError" in out
    assert "make sim SEED=77" in out
