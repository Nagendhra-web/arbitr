"""Enforce per-package coverage floors from a coverage.py JSON report.

At least 95% on core/, policy/, preview/, the executor and the credential providers (the
overall 90% floor is enforced by pytest-cov). A package with no statements yet
is reported as such, so an empty package never looks like a covered one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FLOORS = {
    "src/arbitr/core/": 95.0,
    "src/arbitr/policy/": 95.0,
    "src/arbitr/executor.py": 95.0,
    "src/arbitr/credentials.py": 95.0,
    "src/arbitr/preview/": 95.0,
}


def main(report_path: str) -> int:
    files = json.loads(Path(report_path).read_text(encoding="utf-8"))["files"]
    failed = False
    for prefix, floor in FLOORS.items():
        stmts = covered = 0
        for name, data in files.items():
            if name.replace("\\", "/").startswith(prefix):
                stmts += data["summary"]["num_statements"]
                covered += data["summary"]["covered_lines"]
        if stmts == 0:
            print(f"{prefix}: no statements yet (floor {floor}% applies once code lands)")
            continue
        pct = 100.0 * covered / stmts
        status = "ok" if pct >= floor else "BELOW FLOOR"
        print(f"{prefix}: {pct:.2f}% of {stmts} statements (floor {floor}%) {status}")
        failed = failed or pct < floor
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
