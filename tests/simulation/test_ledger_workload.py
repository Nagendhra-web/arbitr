"""The real executor under the simulator: determinism, fault coverage and the checker."""

from __future__ import annotations

import argparse
from collections import Counter
from typing import TYPE_CHECKING

import pytest
from engine import Simulator, Sleep, Step
from fiber import Fiber, Killed
from ledger_workload import EPOCH, LedgerWorkload, run_ledger_seed, seeded_ids
from run import LEDGER_SHARE, plan, regression_seeds
from workloads import InvariantError

import arbitr.core.intent
import arbitr.executor
from arbitr.core.intent import new_ulid
from arbitr.executor import Ledger, _Plan

if TYPE_CHECKING:
    from arbitr.core.states import IntentState

EXECUTOR_STEPS = {
    "after_decision_commit",
    "before_executing_commit",
    "after_executing_commit",
    "before_call",
    "after_side_effect",
}


# ------------------------------------------------------------ fibers


def test_a_fiber_runs_only_between_resume_and_pause() -> None:
    log: list[str] = []

    def body(fiber: Fiber) -> None:
        log.append("a")
        fiber.pause(Step("one"))
        log.append("b")
        fiber.pause(Sleep(2.0))
        log.append("c")

    fiber = Fiber("f", body)
    assert log == []
    assert fiber.resume() == Step("one")
    assert log == ["a"]
    assert fiber.resume() == Sleep(2.0)
    assert log == ["a", "b"]
    assert fiber.resume() is None
    assert log == ["a", "b", "c"]
    assert fiber.done


def test_a_killed_fiber_runs_nothing_after_its_pause() -> None:
    log: list[str] = []

    def body(fiber: Fiber) -> None:
        try:
            fiber.pause(Step("one"))
            log.append("after the kill")
        except Exception:  # noqa: BLE001 - fiber code catching errors must not catch a kill
            log.append("caught")

    fiber = Fiber("f", body)
    fiber.resume()
    fiber.kill()
    assert fiber.done
    assert log == []


def test_a_fiber_error_reaches_the_simulator() -> None:
    def body(fiber: Fiber) -> None:
        fiber.pause(Step("one"))
        raise ValueError("bug in the code under test")

    fiber = Fiber("f", body)
    fiber.resume()
    with pytest.raises(ValueError, match="bug in the code"):
        fiber.resume()


def test_killed_is_not_an_exception() -> None:
    assert not issubclass(Killed, Exception)


# ------------------------------------------------------------ ids


def test_seeded_ids_repeat_and_are_restored() -> None:
    sim = Simulator(1)
    with seeded_ids(sim.clock, 5):
        first = [arbitr.core.intent.new_ulid() for _ in range(3)]
    with seeded_ids(sim.clock, 5):
        again = [arbitr.core.intent.new_ulid() for _ in range(3)]
    assert first == again
    assert len(set(first)) == 3
    assert first[0][:10] == new_ulid(int(EPOCH.timestamp() * 1000), bytes(10))[:10]
    assert arbitr.core.intent.new_ulid is new_ulid
    assert vars(arbitr.executor)["new_ulid"] is new_ulid


# ------------------------------------------------------------ determinism


@pytest.mark.parametrize("seed", [0, 3, 7])
def test_same_seed_same_ledger_history(seed: int) -> None:
    """The digest covers the simulator history and every ledger event, hashes included."""
    assert run_ledger_seed(seed) == run_ledger_seed(seed)


def test_different_seeds_give_different_ledger_histories() -> None:
    assert len({run_ledger_seed(s) for s in range(6)}) == 6


# ------------------------------------------------------------ coverage


def tally(workload: LedgerWorkload, seen: Counter[str]) -> None:
    """Count what one seed exercised: kills by step, cancels, scheduler runs, effects."""
    seen.update(f"killed {at}" for at in workload.kills)
    seen[f"on_unknown {workload.on_unknown}"] += 1
    for event in workload.sim.history:
        if event["kind"] == "cancel":
            seen[f"cancel {event['outcome']}"] += 1
        if event["kind"] in ("run_due", "final_run_due"):
            seen.update(f"run_due {action}" for action in event["actions"])
        if event["kind"] == "effect":
            seen[f"effect {event['mode']}"] += 1


def test_seeds_cover_every_step_crash_and_the_cancel_window() -> None:
    seen: Counter[str] = Counter()
    for seed in range(60):
        run_ledger_seed(seed, observe=lambda w: tally(w, seen))
    for step in EXECUTOR_STEPS:
        assert seen[f"killed {step}"] > 0, step
    for key in ("cancel cancelled", "cancel too_late", "run_due ran"):
        assert seen[key] > 0, key
    for mode in ("native", "probe", "none", "delayed"):
        assert seen[f"effect {mode}"] > 0, mode
    for rule in ("require_approval", "fail", "retry"):
        assert seen[f"on_unknown {rule}"] > 0, rule


# ------------------------------------------------------------ the checker


def test_checker_catches_a_tool_that_lies_about_idempotency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The probe tool claims native idempotency, but its service does not deduplicate."""
    import ledger_workload  # noqa: PLC0415

    real = ledger_workload.specs_for

    def lying(on_unknown: str) -> dict[ledger_workload.Mode, object]:
        specs = dict(real(on_unknown))
        specs["probe"] = specs["probe"].model_copy(update={"idempotency": "native", "probe": None})
        return specs  # type: ignore[return-value]

    monkeypatch.setattr(ledger_workload, "specs_for", lying)
    assert first_failure(range(80)).startswith("AtMostOnceEffect")


def test_checker_catches_a_call_without_an_executing_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mutant executor that skips the EXECUTING commit before calling the tool."""

    def skip_commit(self: Ledger, plan: _Plan, expected: IntentState) -> _Plan:
        self._step("before_executing_commit")
        return _Plan(plan.intent, 1, plan.start_from)

    import ledger_workload  # noqa: PLC0415

    monkeypatch.setattr(Ledger, "_start", skip_commit)
    # The lease check before the call would refuse (there is no EXECUTING record
    # to renew), so the mutant must skip it too to reach the service at all.
    monkeypatch.setattr(Ledger, "_confirm_lease", lambda self, plan: None)
    monkeypatch.setattr(ledger_workload, "WEIGHTS", (1.0, 0.0, 0.0, 0.0))  # every call succeeds
    assert first_failure(range(10)).startswith("NoExecuteWithoutLedger")


def first_failure(seeds: range) -> str:
    """The invariant message of the first failing seed (without the seed prefix)."""
    for seed in seeds:
        try:
            run_ledger_seed(seed)
        except InvariantError as exc:
            return str(exc).split(": ", 1)[1]
    return "no seed failed"


@pytest.mark.parametrize("seed", [119, 184])
def test_regression_seeds_catch_a_none_tool_rerun_after_unknown(
    monkeypatch: pytest.MonkeyPatch, seed: int
) -> None:
    """Undo the fix that stops a none tool re-running from FAILED after UNKNOWN."""
    monkeypatch.setattr(arbitr.executor, "_may_have_acted", lambda tx, spec, row: False)
    with pytest.raises(InvariantError, match="NoSilentRetry"):
        run_ledger_seed(seed)


# ------------------------------------------------------------ the runner


def test_run_plans_a_share_of_seeds_on_the_ledger() -> None:
    args = argparse.Namespace(seed=None, seeds=80, start=0, ledger_seeds=None)
    jobs = plan(args)
    regressions = len(regression_seeds())
    assert sum(1 for j in jobs if j[0] == "counter") == 80 + regressions
    assert sum(1 for j in jobs if j[0] == "ledger") == 80 // LEDGER_SHARE + regressions


def test_a_replayed_seed_runs_both_workloads() -> None:
    args = argparse.Namespace(seed=12, seeds=None, start=0, ledger_seeds=None)
    assert [(name, seed) for name, _, seed in plan(args)] == [("counter", 12), ("ledger", 12)]
