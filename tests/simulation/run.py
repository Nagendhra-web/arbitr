"""Run deterministic simulation seeds.

    python tests/simulation/run.py --seeds 2000           seeds 0..1999 (make ci)
    python tests/simulation/run.py --seed 1234 --verbose  replay one seed (make sim SEED=1234)

Seeds listed in regression_seeds.txt always run first. Any failing seed must
be added there so it stays a permanent regression test.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from engine import FaultPlan, Simulator
from workloads import CounterWorkload

REGRESSIONS = Path(__file__).with_name("regression_seeds.txt")


def run_seed(seed: int, *, verbose: bool = False) -> str:
    """Run one seed, check invariants, return the history digest."""
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Run deterministic simulation seeds.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--seed", type=int, help="replay a single seed")
    group.add_argument("--seeds", type=int, help="run seeds start..start+N-1 plus regressions")
    parser.add_argument("--start", type=int, default=0, help="first seed for --seeds")
    parser.add_argument("--verbose", action="store_true", help="print the history")
    args = parser.parse_args()

    if args.seed is not None:
        seeds = [args.seed]
    else:
        seeds = regression_seeds() + list(range(args.start, args.start + args.seeds))
    began = time.perf_counter()
    for seed in seeds:
        try:
            run_seed(seed, verbose=args.verbose)
        except Exception as exc:  # noqa: BLE001, any failure must name its seed
            print(f"FAILED seed {seed}: {type(exc).__name__}: {exc}")
            print(f"Replay with: make sim SEED={seed}")
            return 1
    elapsed = time.perf_counter() - began
    print(f"simulation: {len(seeds)} seeds passed in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
