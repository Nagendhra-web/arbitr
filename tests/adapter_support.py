"""What the framework adapter tests share: a policy, a key and tool specs."""

from __future__ import annotations

from arbitr.core.spec import ToolSpec
from arbitr.policy.schema import load_policy

KEY = b"integration-tests" + b"!" * 15
POLICY = load_policy("""
version: 1
default: { write: allow, financial: allow, read: allow }
rules:
  - id: no-destructive-sql
    when: { tool: db.execute, effect: destructive }
    then: deny
    reason: Agents may not run destructive SQL.
  - id: big-refunds
    when: { tool: payments.refund, args: [{ path: "$.amount", op: gt, value: 100 }] }
    then: require_approval
    reason: Refunds over 100 need a human.
""")
REFUND = ToolSpec(name="payments.refund", effect="financial", idempotency="native")
SQL = ToolSpec(name="db.execute", effect="write")
SPECS = {"refund": REFUND, "run_sql": SQL}
