"""The guard decorator: sync and async tools through the ledger, with injected keys."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

import arbitr
from arbitr import ActionDenied, ApprovalPending, Ledger, ToolSpec, guard
from arbitr.core.errors import RunContextError
from arbitr.policy.schema import load_policy

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"guard-decorator!" * 2
POLICY = load_policy("""
version: 1
default: { write: allow, financial: allow }
rules:
  - id: no-drop
    when: { tool: db.execute, effect: destructive }
    then: deny
    reason: Agents may not drop tables.
  - id: big-refunds
    when: { tool: payments.refund, args: [{ path: "$.amount", op: gt, value: 100 }] }
    then: require_approval
    reason: Refunds over 100 need a human.
""")
REFUND = ToolSpec(name="payments.refund", effect="financial", idempotency="native")
SQL = ToolSpec(name="db.execute", effect="write")


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY, worker_id="w1") as led:
        yield led


def test_sync_tool_runs_once_and_a_retry_gets_the_receipt(ledger: Ledger) -> None:
    calls: list[tuple[str, float, str | None]] = []

    @guard(ledger, REFUND)
    def refund(order_id: str, amount: float, *, idempotency_key: str | None = None) -> dict:
        calls.append((order_id, amount, idempotency_key))
        return {"refund_id": "re_1", "order_id": order_id}

    with ledger.run(principal="alice", agent_id="bot"):
        first = refund("o-1", 25)
        second = refund("o-1", amount=25)

    assert first == second == {"refund_id": "re_1", "order_id": "o-1"}
    assert len(calls) == 1
    assert calls[0][2]  # the ledger's idempotency key was injected


def test_async_tool_runs_through_aexecute(ledger: Ledger) -> None:
    calls: list[str] = []

    @guard(ledger, REFUND)
    async def refund(order_id: str, amount: float, *, idempotency_key: str | None = None) -> dict:
        await asyncio.sleep(0)
        calls.append(order_id)
        return {"refund_id": "re_2"}

    assert asyncio.iscoroutinefunction(refund)

    async def main() -> object:
        with ledger.run(principal="alice", agent_id="bot"):
            await refund("o-2", 10)
            return await refund("o-2", 10)

    assert asyncio.run(main()) == {"refund_id": "re_2"}
    assert calls == ["o-2"]


def test_denial_and_approval_raise_before_the_tool_runs(ledger: Ledger) -> None:
    ran: list[object] = []

    @guard(ledger, SQL)
    def run_sql(sql: str) -> str:
        ran.append(sql)
        return "ok"

    @guard(ledger, REFUND)
    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        ran.append(order_id)
        return "ok"

    with ledger.run(principal="alice", agent_id="bot"):
        with pytest.raises(ActionDenied) as denied:
            run_sql("DROP TABLE customers")
        with pytest.raises(ApprovalPending):
            refund("o-3", 500)

    assert denied.value.rule_id == "no-drop"
    assert ran == []


def test_defaults_are_part_of_the_intent(ledger: Ledger) -> None:
    calls: list[str] = []

    @guard(ledger, SQL)
    def run_sql(sql: str, timeout: int = 5) -> str:
        calls.append(sql)
        return "ok"

    with ledger.run(principal="alice", agent_id="bot"):
        run_sql("SELECT 1")
        run_sql("SELECT 1", timeout=5)  # the same call, written differently
        run_sql("SELECT 1", timeout=6)

    assert len(calls) == 2


def test_an_explicit_key_is_used_as_the_idempotency_key(ledger: Ledger) -> None:
    seen: list[str | None] = []

    @guard(ledger, REFUND)
    def refund(order_id: str, amount: float, *, idempotency_key: str | None = None) -> str:
        seen.append(idempotency_key)
        return "ok"

    with ledger.run(principal="alice", agent_id="bot"):
        refund("o-4", 1, idempotency_key="order-o-4-refund")
        refund("o-4", 1, idempotency_key="order-o-4-refund")

    assert seen == ["order-o-4-refund"]


def test_the_ledger_can_be_given_lazily(ledger: Ledger) -> None:
    @guard(lambda: ledger, SQL)
    def run_sql(sql: str) -> str:
        return sql

    with ledger.run(principal="alice", agent_id="bot"):
        assert run_sql("SELECT 2") == "SELECT 2"


def test_calls_outside_a_run_are_refused(ledger: Ledger) -> None:
    @guard(ledger, SQL)
    def run_sql(sql: str) -> str:
        return sql

    with pytest.raises(RunContextError):
        run_sql("SELECT 1")


def test_wrapper_keeps_the_function_metadata(ledger: Ledger) -> None:
    @guard(ledger, SQL)
    def run_sql(sql: str) -> str:
        """Run SQL."""
        return sql

    assert run_sql.__name__ == "run_sql"
    assert run_sql.__doc__ == "Run SQL."
    assert run_sql.__wrapped__ is not None  # type: ignore[attr-defined]
    assert run_sql.spec is SQL  # type: ignore[attr-defined]


def test_shapes_the_ledger_cannot_call_are_refused_when_decorating(ledger: Ledger) -> None:
    with pytest.raises(TypeError, match="positional-only"):

        @guard(ledger, SQL)
        def positional(sql: str, /) -> str:
            return sql

    with pytest.raises(TypeError, match=r"\*args"):

        @guard(ledger, SQL)
        def star(*sql: str) -> str:
            return ""

    with pytest.raises(TypeError, match="idempotency_key"):

        @guard(ledger, REFUND)
        def no_key(order_id: str) -> str:
            return order_id

    creds = ToolSpec(name="crm.update", effect="write", credentials=("crm",))
    with pytest.raises(TypeError, match="credentials"):

        @guard(ledger, creds)
        def no_creds(contact: str) -> str:
            return contact


def test_callers_cannot_pass_credentials(ledger: Ledger) -> None:
    creds = ToolSpec(name="crm.update", effect="write", credentials=("crm",))

    @guard(ledger, creds)
    def update(contact: str, credentials: dict | None = None) -> str:
        return contact

    with ledger.run(principal="alice", agent_id="bot"), pytest.raises(TypeError, match="injected"):
        update("c-1", credentials={"crm": "stolen"})


def test_var_keyword_arguments_become_named_arguments(ledger: Ledger) -> None:
    got: list[dict[str, object]] = []

    @guard(ledger, SQL)
    def run_sql(sql: str, **options: object) -> str:
        got.append(options)
        return sql

    with ledger.run(principal="alice", agent_id="bot"):
        run_sql("SELECT 3", timeout=1)

    assert got == [{"timeout": 1}]


def test_public_names_are_exported() -> None:
    names = ("Ledger", "ToolSpec", "guard", "ActionDenied", "ApprovalPending", "ApprovalRejected",
             "InFlight", "UnknownOutcome", "LedgerUnavailable")  # fmt: skip
    for name in names:
        assert name in arbitr.__all__
        assert getattr(arbitr, name) is not None
    with pytest.raises(AttributeError):
        _ = arbitr.not_a_name  # type: ignore[attr-defined]


def test_a_fixed_step_id_is_refused_for_tools_that_allow_duplicates(ledger: Ledger) -> None:
    email = ToolSpec(name="email.send", effect="external_comm", allow_duplicates=True)
    with pytest.raises(TypeError, match="allows duplicates"):
        guard(ledger, email, step_id="welcome")
    guard(ledger, email)  # without a step id each call is its own action
    guard(ledger, SQL, step_id="nightly")  # fine where duplicates are not allowed
