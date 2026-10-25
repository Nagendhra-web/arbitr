"""Separate processes reserving one budget never spend past its limit."""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

from arbitr.core.redact import Redactor
from arbitr.storage.sqlite import SQLiteStorage

if TYPE_CHECKING:
    from pathlib import Path

KEY = b"process-budget-k" * 2
PROCESSES = 8
ATTEMPTS = 30
LIMIT = 100.0

WORKER = """
import sys
from arbitr.core.redact import Redactor
from arbitr.storage.sqlite import SQLiteStorage
path, key = sys.argv[1], bytes.fromhex(sys.argv[2])
won = 0
with SQLiteStorage.open(path, Redactor(key), busy_timeout_ms=60_000) as db:
    for _ in range({attempts}):
        with db.transaction() as tx:
            if tx.reserve_budget("rule:cap|run:r", 1.0, {limit}):
                won += 1
print(won)
"""


def test_processes_racing_on_one_budget_never_overspend(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with SQLiteStorage.open(path, Redactor(KEY)) as db, db.transaction() as tx:
        tx.insert_run("r", "alice", "bot")
    script = WORKER.format(attempts=ATTEMPTS, limit=LIMIT)
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(path), KEY.hex()],
            stdout=subprocess.PIPE,
            text=True,
        )
        for _ in range(PROCESSES)
    ]
    won = 0
    for worker in workers:
        out, _ = worker.communicate(timeout=240)
        assert worker.returncode == 0
        won += int(out.strip())

    assert won == LIMIT  # 240 attempts for 100 units: exactly 100 succeed
    with SQLiteStorage.open(path, Redactor(KEY)) as db:
        with db.transaction() as tx:
            assert tx.budget_counters(["rule:cap|run:r"]) == {"rule:cap|run:r": LIMIT}
        assert db.verify().ok
