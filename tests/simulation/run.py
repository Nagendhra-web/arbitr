"""Run deterministic simulation seeds.

    python tests/simulation/run.py --seeds 2000           seeds 0..1999 (make ci)
    python tests/simulation/run.py --seed 1234 --verbose  replay one seed (make sim SEED=1234)

There are two workloads. The counter workload is a fast toy. The ledger
workload drives the real executor and SQLite ledger. ``--seeds N`` runs both on
every seed (or the ledger workload on ``--ledger-seeds`` seeds), spread over
``--jobs`` processes; each seed is independent and deterministic, so the
result does not depend on the number of processes. ``--seed`` replays one seed
on both workloads in this process.

Seeds listed in regression_seeds.txt always run first, on both workloads.
Any failing seed must be added there so it stays a permanent regression test.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(1, str(Path(__file__).resolve().parents[2]))  # the bench fakes

from engine import FaultPlan, Simulator
from ledger_workload import run_ledger_seed
from workloads import CounterWorkload

if TYPE_CHECKING:
    from collections.abc import Callable

REGRESSIONS = Path(__file__).with_name("regression_seeds.txt")
LEDGER_SHARE = 1
"""``--seeds N`` runs the ledger workload on N // LEDGER_SHARE seeds (all of them)."""


def run_seed(seed: int, *, verbose: bool = False) -> str:
    """Run one seed of the counter workload, check invariants, return the history digest."""
    sim = Simulator(seed, FaultPlan(crash_probability=0.05, max_crashes=10))
    workload = CounterWorkload(sim)
    sim.run()
    if verbose:
        for event in sim.history:
            print(event)
    workload.check()
    return sim.history_digest()


def regression_seeds() -> list[int]:
    """Seeds from regression_seeds.txt (one per line, ``#`` comments allowed)."""
    if not REGRESSIONS.exists():
        return []
    seeds = []
    for line in REGRESSIONS.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            seeds.append(int(value))
    return seeds


def plan(args: argparse.Namespace) -> list[tuple[str, Callable[..., str], int]]:
    """The (workload, runner, seed) jobs to run, regressions first."""
    if args.seed is not None:
        return [("counter", run_seed, args.seed), ("ledger", run_ledger_seed, args.seed)]
    regressions = regression_seeds()
    count = args.seeds // LEDGER_SHARE if args.ledger_seeds is None else args.ledger_seeds
    counter = regressions + list(range(args.start, args.start + args.seeds))
    ledger = regressions + list(range(args.start, args.start + count))
    return [("counter", run_seed, s) for s in counter] + [
        ("ledger", run_ledger_seed, s) for s in ledger
    ]


def run_job(job: tuple[str, Callable[..., str], int], *, verbose: bool = False) -> str | None:
    """Run one (workload, runner, seed) job. Returns None, or the failure as text."""
    _, runner, seed = job
    try:
        runner(seed, verbose=verbose)
    except Exception as exc:  # noqa: BLE001, any failure must name its seed
        return f"{type(exc).__name__}: {exc}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Run deterministic simulation seeds.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--seed", type=int, help="replay a single seed on both workloads")
    group.add_argument("--seeds", type=int, help="run seeds start..start+N-1 plus regressions")
    parser.add_argument("--start", type=int, default=0, help="first seed for --seeds")
    parser.add_argument(
        "--ledger-seeds", type=int, help=f"ledger workload seeds (default: N // {LEDGER_SHARE})"
    )
    parser.add_argument("--verbose", action="store_true", help="print the history")
    parser.add_argument(
        "--jobs", type=int, default=os.cpu_count() or 1, help="processes (default: one per CPU)"
    )
    args = parser.parse_args()

    jobs = plan(args)
    began = time.perf_counter()
    if args.seed is not None or args.jobs <= 1:
        outcomes = [run_job(job, verbose=args.verbose) for job in jobs]
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            outcomes = list(pool.map(run_job, jobs, chunksize=16))
    for (workload, _, seed), failure in zip(jobs, outcomes, strict=True):
        if failure is not None:  # the first failure in plan order, regressions first
            print(f"FAILED seed {seed}: {failure} ({workload} workload)")
            print(f"Replay with: make sim SEED={seed}")
            return 1
    elapsed = time.perf_counter() - began
    counts = {name: sum(1 for job in jobs if job[0] == name) for name in ("counter", "ledger")}
    print(
        f"simulation: {counts['counter']} counter seeds and {counts['ledger']} ledger seeds"
        f" passed in {elapsed:.1f}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
