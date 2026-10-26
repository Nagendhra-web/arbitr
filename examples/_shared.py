"""What every example shares: the policy, the tool specs and a fresh ledger.

The story is the same in each example. A support agent refunds a small
order, retries the same refund, tries to drop a table, and asks for a refund
too large to make without a person.
"""

from __future__ import annotations

import secrets
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from arbitr import Ledger, ToolSpec
from arbitr.policy.schema import load_policy

if TYPE_CHECKING:
    from collections.abc import Iterator

POLICY = load_policy("""
version: 1
default: { financial: allow }
rules:
  - id: no-destructive-sql
    when: { tool: db.execute, effect: destructive }
    then: deny
    reason: Agents may not run destructive SQL.
  - id: big-refunds
    when:
      tool: payments.refund
      args: [{ path: "$.amount", op: gt, value: 100 }]
    then: require_approval
    reason: Refunds over 100 need a human.
""")

REFUND = ToolSpec(name="payments.refund", effect="financial", idempotency="native")
RUN_SQL = ToolSpec(name="db.execute", effect="write")
SPECS = {"refund": REFUND, "run_sql": RUN_SQL}

# The scripted conversation: the model's tool calls, turn by turn.
SCRIPT: list[object] = [
    [("refund", {"order_id": "o-1", "amount": 25})],
    [("refund", {"order_id": "o-1", "amount": 25})],
    [("run_sql", {"sql": "DROP TABLE orders"})],
    [("refund", {"order_id": "o-2", "amount": 500})],
    "Refunded o-1. The large refund for o-2 is waiting for approval.",
]


@contextmanager
def fresh_ledger() -> Iterator[Ledger]:
    """A ledger in a temporary folder, removed afterwards."""
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "arbitr.db"
        with Ledger.open(path, POLICY, key=secrets.token_bytes(32)) as ledger:
            yield ledger


def report(outputs: list[str], refunds: int, ledger: Ledger) -> None:
    """Print what the model saw for each call, and what really happened."""
    for number, text in enumerate(outputs, 1):
        print(f"tool call {number}: {text}")
    print(f"refunds made: {refunds}")
    print(f"audit chain ok: {ledger.verify().ok}")
