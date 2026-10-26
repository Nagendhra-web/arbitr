"""The testing kit: fixtures, assertions, fakes and crash injection."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from arbitr import ApprovalPending, ToolSpec, guard
from arbitr.core.errors import ActionDenied, UnknownOutcome
from arbitr.policy.schema import Policy, load_policy
from arbitr.testing import (
    CRASH_POINTS,
    FakePayments,
    FakeTool,
    LostResponse,
    SimulatedCrash,
    TestRun,
    assert_denied,
    assert_exactly_once,
    assert_needs_approval,
    assert_no_effect,
    assert_not_run,
    crash_at,
    restart,
)
from arbitr.testing.plugin import as_policy

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from arbitr.executor import Ledger

POLICY = """
version: 1
default: { financial: allow }
rules:
  - id: no-destructive-sql
    when: { tool: db.execute, effect: destructive }
    then: deny
    reason: Agents may not run destructive SQL.
  - id: big-refunds
    when: { tool: payments.refund, args: [{ path: "$.amount", op: gt, value: 100 }] }
    then: require_approval
    reason: Refunds over 100 need a human.
"""
REFUND = ToolSpec(name="payments.refund", effect="financial", idempotency="native")
SQL = ToolSpec(name="db.execute", effect="write")
EMAIL = ToolSpec(name="email.send", effect="external_comm")


@pytest.fixture
def arbitr_policy() -> str:
    return POLICY


@pytest.fixture
def payments() -> Iterator[FakePayments]:
    service = FakePayments()
    yield service
    service.close()


def refund_tool(ledger: Ledger, payments: FakePayments) -> Callable[..., object]:
    @guard(ledger, REFUND)
    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
        return payments.refund(order_id, amount, idempotency_key=idempotency_key)

    return refund


# ------------------------------------------------------------------ fixtures


def test_fixtures_give_a_ledger_and_an_active_run(
    arbitr_ledger: Ledger, arbitr_run: TestRun
) -> None:
    assert arbitr_run.ledger is arbitr_ledger
    record = arbitr_ledger.run_record(arbitr_run.run_id)
    assert record is not None
    assert (record.principal, record.agent_id) == ("test-user", "test-agent")
    assert arbitr_run.intents() == []


def test_as_policy_takes_a_policy_a_path_or_yaml(tmp_path: Path) -> None:
    file = tmp_path / "policy.yaml"
    file.write_text(POLICY, encoding="utf-8")
    policy = load_policy(POLICY)
    for value in (policy, file, str(file), POLICY):
        assert isinstance(as_policy(value), Policy)
    assert as_policy(policy) is policy


# ------------------------------------------------------------------ assertions


def test_assertions_pass_for_a_well_behaved_agent(
    arbitr_ledger: Ledger, arbitr_run: TestRun, payments: FakePayments
) -> None:
    refund = refund_tool(arbitr_ledger, payments)
    sql = FakeTool(SQL, returns="ok")
    run_sql = guard(arbitr_ledger, SQL)(sql)

    refund("o-1", 25)
    refund("o-1", 25)  # a retry: the receipt comes back
    with pytest.raises(ActionDenied):
        run_sql(sql="DROP TABLE orders")
    with pytest.raises(ApprovalPending):
        refund("o-2", 500)

    assert_exactly_once(arbitr_run, "payments.refund", args={"order_id": "o-1"})
    assert_no_effect(arbitr_run, "destructive")
    assert_denied(arbitr_run, tool="db.execute", rule="no-destructive-sql")
    assert_denied(arbitr_run, rule="no-destructive-sql", args={"sql": "DROP TABLE orders"})
    assert_needs_approval(arbitr_run, tool="payments.refund", rule="big-refunds")
    assert_not_run(arbitr_run, "db.execute")
    assert_not_run(arbitr_run, "payments.refund", args={"order_id": "o-2"})
    assert sql.count == 0


def test_assertions_fail_with_the_actions_listed(
    arbitr_ledger: Ledger, arbitr_run: TestRun, payments: FakePayments
) -> None:
    refund = refund_tool(arbitr_ledger, payments)
    refund("o-1", 25)
    refund("o-3", 30)
    shell = guard(arbitr_ledger, ToolSpec(name="shell.run", effect="write"))(FakeTool(SQL))
    with pytest.raises(ApprovalPending):  # rm -rf counts as destructive: approval by default
        shell(command="rm -rf /data")

    with pytest.raises(AssertionError, match=r"started 2 time\(s\)"):
        assert_exactly_once(arbitr_run, "payments.refund")
    with pytest.raises(AssertionError, match="no calls"):
        assert_exactly_once(arbitr_run, "email.send")
    with pytest.raises(AssertionError, match=r"payments.refund ran 2 time"):
        assert_not_run(arbitr_run, "payments.refund")
    with pytest.raises(AssertionError, match=r"no action denied \(tool=payments.refund\)"):
        assert_denied(arbitr_run, tool="payments.refund")
    with pytest.raises(AssertionError, match="no action waiting for approval"):
        assert_needs_approval(arbitr_run, tool="payments.refund")
    assert_needs_approval(arbitr_run, tool="shell.run")
    assert_no_effect(arbitr_run, "destructive")  # it never ran
    with pytest.raises(AssertionError, match="2 financial action"):
        assert_no_effect(arbitr_run, "financial")


def test_args_that_do_not_match_or_cannot_be_read(
    arbitr_ledger: Ledger, arbitr_run: TestRun
) -> None:
    send = guard(arbitr_ledger, EMAIL)(FakeTool(EMAIL, returns={"id": "m1"}))
    send(to="a@example.com")
    assert_exactly_once(arbitr_run, "email.send", args={"to": "a@example.com"})
    with pytest.raises(AssertionError):
        assert_exactly_once(arbitr_run, "email.send", args={"to": "b@example.com"})


# ------------------------------------------------------------------ fakes


def test_fake_tool_returns_raises_or_loses_the_response() -> None:
    tool = FakeTool(EMAIL, returns=lambda to: {"sent_to": to})
    assert tool(to="x@example.com") == {"sent_to": "x@example.com"}
    assert tool.name == "email.send"

    broken = FakeTool(EMAIL, raises=PermissionError("no"))
    with pytest.raises(PermissionError):
        broken(to="x")
    assert broken.count == 0

    lost = FakeTool(EMAIL, lose_response=True)
    with pytest.raises(LostResponse):
        lost(to="x")
    assert lost.count == 1  # it acted before the reply was lost


def test_fake_payments_probe_and_crash(tmp_path: Path) -> None:
    service = FakePayments(tmp_path / "pay.db", native=False, crash_after_effect=True)
    with pytest.raises(LostResponse):
        service.refund("o-1", 5, idempotency_key="k1")
    assert service.count("o-1") == 1
    assert service.find_refund("o-1", "k1") is not None
    assert service.find_refund("o-2", "k1") is None
    service.close()


# ------------------------------------------------------------------ crash injection


@pytest.mark.parametrize("point", sorted(CRASH_POINTS))
def test_native_tools_stay_exactly_once_through_a_crash(
    point: str, arbitr_ledger: Ledger, arbitr_run: TestRun, payments: FakePayments
) -> None:
    refund = refund_tool(arbitr_ledger, payments)
    with crash_at(arbitr_ledger, point), pytest.raises(SimulatedCrash):  # type: ignore[arg-type]
        refund("o-1", 25)
    assert arbitr_run.intents()[0].state.value == "EXECUTING"  # the dead worker's lease

    restart(arbitr_ledger)
    result = refund("o-1", 25)

    assert payments.count() == 1
    assert result == {"refund_id": "re_000001", "order_id": "o-1", "amount": 25.0}
    assert arbitr_run.intents()[0].state.value == "SUCCEEDED"


def test_a_tool_without_idempotency_is_unknown_after_a_crash(
    arbitr_ledger: Ledger, arbitr_run: TestRun
) -> None:
    fake = FakeTool(EMAIL, returns={"id": "m1"})
    send = guard(arbitr_ledger, EMAIL)(fake)
    with crash_at(arbitr_ledger, "after_tool"), pytest.raises(SimulatedCrash):
        send(to="a@example.com")

    restart(arbitr_ledger)
    with pytest.raises(UnknownOutcome):  # it may have sent: it is not sent again
        send(to="a@example.com")
    assert fake.count == 1


def test_crash_at_only_fires_once_and_restores_the_hook(
    arbitr_ledger: Ledger, arbitr_run: TestRun
) -> None:
    seen: list[str] = []
    arbitr_ledger.on_step = seen.append
    send = guard(arbitr_ledger, EMAIL)(FakeTool(EMAIL, returns="ok"))
    with crash_at(arbitr_ledger, "before_tool"):
        with pytest.raises(SimulatedCrash):
            send(to="a@example.com")
        assert send(to="b@example.com") == "ok"  # the crash fired once
    assert arbitr_ledger.on_step == seen.append
    assert "after_executing_commit" in seen
    with pytest.raises(ValueError, match="crash point"), crash_at(arbitr_ledger, "sometime"):  # type: ignore[arg-type]
        pass  # pragma: no cover
