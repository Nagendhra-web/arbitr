"""The executor: every call goes through the ledger and the gate, exactly once."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

import pytest
from bench.fakes.payments import FakePayments

from arbitr.core.errors import (
    ActionDenied,
    ApprovalPending,
    InFlight,
    LedgerUnavailable,
    RunContextError,
    StorageError,
    UnknownOutcome,
)
from arbitr.core.scope import Scope
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.credentials import EnvCredentials
from arbitr.executor import Ledger, current_run
from arbitr.policy.schema import load_policy

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"executor-tests!!" * 2
POLICY = load_policy(
    """
version: 1
include: [lethal-trifecta]
rules:
  - id: big-refunds
    when:
      tool: payments.refund
      args: [{ path: "$.amount", op: gt, value: 100 }]
    then: require_approval
    reason: Refunds over 100 need a human.
  - id: refund-cap
    when:
      tool: payments.refund
      args: [{ path: "$.amount", op: lte, value: 100 }]
    budget: { scope: [run], sum_path: "$.amount", limit: 50 }
    then_exceeded: deny
    reason: Refund cap for the run.
  - id: no-drops
    when: { tool: db.exec, effect: destructive }
    then: deny
    reason: No destructive SQL.
  - id: refunds-allowed
    when: { tool: payments.refund }
    then: allow
    reason: Refunds are allowed.
"""
)
REFUND = ToolSpec(
    name="payments.refund", effect="financial", idempotency="native",
    probe="bench.fakes.probes:find_refund",
)  # fmt: skip
PLAIN_REFUND = ToolSpec(name="payments.refund", effect="financial")


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "ledger.db", POLICY, key=KEY, worker_id="w1") as led:
        yield led


@pytest.fixture
def payments() -> Iterator[FakePayments]:
    service = FakePayments()
    yield service
    service.close()


@pytest.fixture
def plain_payments() -> Iterator[FakePayments]:
    """A payments service without native idempotency: every call refunds."""
    service = FakePayments(native=False)
    yield service
    service.close()


def refund_fn(service: FakePayments) -> Any:
    def call(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
        return service.refund(order_id, amount, idempotency_key=idempotency_key)

    return call


class _Crash(BaseException):
    """Stands in for the worker process dying."""


def crash_before_call(ledger: Ledger, spec: ToolSpec, args: dict[str, object]) -> str:
    """Run the protocol until EXECUTING is committed, then 'crash' before the tool runs."""

    def stop(step: str) -> None:
        if step == "after_executing_commit":
            raise _Crash

    ledger.on_step = stop
    try:
        ledger.execute(spec, args, lambda **kwargs: None)
    except _Crash:
        pass
    finally:
        ledger.on_step = None
    run = current_run()
    assert run is not None
    return run.last_idempotency_key


# ---------------------------------------------------------------- happy path


def test_an_allowed_action_runs_once_and_is_recorded(
    ledger: Ledger, payments: FakePayments
) -> None:
    with ledger.run("alice", "bot") as run:
        result = ledger.execute(REFUND, {"order_id": "o1", "amount": 20}, refund_fn(payments))
    assert result == {"refund_id": "re_000001", "order_id": "o1", "amount": 20.0}
    assert payments.count() == 1
    row = ledger.intent_by_key(run.last_idempotency_key)
    assert row is not None
    assert (row.state, row.decision, row.decision_rule) == (
        IntentState.SUCCEEDED, "allow", "refunds-allowed",
    )  # fmt: skip
    assert ledger.verify().ok


def test_a_repeated_call_returns_the_receipt_without_running_again(
    ledger: Ledger, payments: FakePayments
) -> None:
    with ledger.run("alice", "bot", run_id="r1"):
        first = ledger.execute(REFUND, {"order_id": "o1", "amount": 20}, refund_fn(payments))
        second = ledger.execute(REFUND, {"order_id": "o1", "amount": 20}, refund_fn(payments))
    assert payments.count() == 1
    assert second == first


def test_native_tools_get_the_idempotency_key(ledger: Ledger) -> None:
    seen: list[str | None] = []

    def tool(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        seen.append(idempotency_key)
        return "ok"

    with ledger.run("alice", "bot") as run:
        ledger.execute(REFUND, {"order_id": "o1", "amount": 1}, tool)
    assert seen == [run.last_idempotency_key]


def test_calls_outside_a_run_are_refused(ledger: Ledger, payments: FakePayments) -> None:
    with pytest.raises(RunContextError):
        ledger.execute(REFUND, {"order_id": "o1", "amount": 1}, refund_fn(payments))
    assert payments.count() == 0


# ---------------------------------------------------------------- decisions


def test_a_denied_action_never_runs(ledger: Ledger) -> None:
    calls: list[str] = []
    spec = ToolSpec(name="db.exec", effect="write")
    with ledger.run("alice", "bot"), pytest.raises(ActionDenied) as err:
        ledger.execute(spec, {"sql": "DROP TABLE users"}, calls.append)
    assert calls == []
    assert err.value.rule_id == "no-drops"
    message = err.value.to_tool_message()
    assert "no-drops" in message
    assert "Do not retry" in message
    assert "DROP" not in message


def test_an_action_needing_approval_waits(ledger: Ledger, payments: FakePayments) -> None:
    args = {"order_id": "o2", "amount": 500}
    with ledger.run("alice", "bot", run_id="r1"):
        with pytest.raises(ApprovalPending) as first:
            ledger.execute(REFUND, args, refund_fn(payments))
        with pytest.raises(ApprovalPending) as again:
            ledger.execute(REFUND, args, refund_fn(payments))
    assert first.value.approval_id == again.value.approval_id
    assert payments.count() == 0


def test_budgets_are_reserved_with_the_decision(ledger: Ledger, payments: FakePayments) -> None:
    with ledger.run("alice", "bot"):
        ledger.execute(REFUND, {"order_id": "a", "amount": 30}, refund_fn(payments))
        with pytest.raises(ActionDenied) as err:
            ledger.execute(REFUND, {"order_id": "b", "amount": 30}, refund_fn(payments))
    assert err.value.rule_id == "refund-cap"
    assert payments.count() == 1


def test_a_failed_tool_releases_its_budget_and_can_retry(ledger: Ledger) -> None:
    attempts: list[int] = []

    def flaky(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        attempts.append(1)
        if len(attempts) == 1:
            raise ValueError("card declined")
        return "ok"

    with ledger.run("alice", "bot", run_id="r1"):
        with pytest.raises(ValueError, match="declined"):
            ledger.execute(REFUND, {"order_id": "a", "amount": 40}, flaky)
        assert ledger.execute(REFUND, {"order_id": "a", "amount": 40}, flaky) == "ok"
    assert len(attempts) == 2
    assert ledger.verify().ok


def test_an_ambiguous_failure_is_recorded_as_unknown(ledger: Ledger) -> None:
    def times_out(order_id: str, amount: float) -> str:
        raise TimeoutError("no response")

    with ledger.run("alice", "bot", run_id="r1") as run:
        with pytest.raises(UnknownOutcome):
            ledger.execute(PLAIN_REFUND, {"order_id": "a", "amount": 5}, times_out)
        row = ledger.intent_by_key(run.last_idempotency_key)
    assert row is not None
    assert row.state == IntentState.UNKNOWN


def test_the_ledger_fails_closed(
    ledger: Ledger, payments: FakePayments, monkeypatch: pytest.MonkeyPatch
) -> None:
    with ledger.run("alice", "bot"):

        def broken(*args: object, **kwargs: object) -> None:
            raise StorageError("disk full")

        monkeypatch.setattr(type(ledger._storage()), "transaction", broken)
        with pytest.raises(LedgerUnavailable) as err:
            ledger.execute(REFUND, {"order_id": "o1", "amount": 5}, refund_fn(payments))
    assert payments.count() == 0
    assert "did not run" in err.value.to_tool_message()


# ---------------------------------------------------------------- leases and recovery


def test_a_running_action_is_in_flight_for_another_worker(
    tmp_path: Path, payments: FakePayments
) -> None:
    path = tmp_path / "ledger.db"
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=60) as one:
        with one.run("alice", "bot", run_id="r1"):
            key = crash_before_call(one, REFUND, {"order_id": "o1", "amount": 5})
        with (
            Ledger.open(path, POLICY, key=KEY, worker_id="w2") as two,
            two.run("alice", "bot", run_id="r1", resume=True),
            pytest.raises(InFlight),
        ):
            two.execute(REFUND, {"order_id": "o1", "amount": 5}, refund_fn(payments))
    assert key
    assert payments.count() == 0


def test_an_expired_native_execution_is_rerun_with_the_same_key(
    tmp_path: Path, payments: FakePayments
) -> None:
    path = tmp_path / "ledger.db"
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=0) as one:
        with one.run("alice", "bot", run_id="r1"):
            key = crash_before_call(one, REFUND, {"order_id": "o1", "amount": 5})
        payments.refund("o1", 5, idempotency_key=key)  # the crashed worker's side effect
        with one.run("alice", "bot", run_id="r1", resume=True):
            again = one.execute(REFUND, {"order_id": "o1", "amount": 5}, refund_fn(payments))
    assert payments.count() == 1  # the service deduplicated the retry
    assert again["refund_id"] == "re_000001"  # type: ignore[index]


def test_a_probe_finds_the_side_effect_without_rerunning(
    tmp_path: Path, plain_payments: FakePayments
) -> None:
    service = plain_payments
    spec = ToolSpec(
        name="payments.refund", effect="financial", idempotency="probe",
        probe="bench.fakes.probes:find_refund",
    )  # fmt: skip
    path = tmp_path / "ledger.db"
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=0) as led:
        led.probe_context["payments"] = service
        with led.run("alice", "bot", run_id="r1"):
            key = crash_before_call(led, spec, {"order_id": "o1", "amount": 5})
        service.refund("o1", 5, idempotency_key=key)
        with led.run("alice", "bot", run_id="r1", resume=True) as run:
            result = led.execute(spec, {"order_id": "o1", "amount": 5}, refund_fn(service))
            row = led.intent_by_key(run.last_idempotency_key)
        assert row is not None
        receipt = led.receipt(row.intent_id)
    assert service.count() == 1
    assert result == {"refund_id": "re_000001", "order_id": "o1", "amount": 5.0}
    assert row.state == IntentState.SUCCEEDED
    assert receipt is not None
    assert receipt.source == "probe"


def test_a_tool_without_idempotency_ends_in_unknown(
    tmp_path: Path, plain_payments: FakePayments
) -> None:
    service = plain_payments
    path = tmp_path / "ledger.db"
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=0) as led:
        with led.run("alice", "bot", run_id="r1"):
            crash_before_call(led, PLAIN_REFUND, {"order_id": "o1", "amount": 5})
        with led.run("alice", "bot", run_id="r1", resume=True), pytest.raises(UnknownOutcome):
            led.execute(PLAIN_REFUND, {"order_id": "o1", "amount": 5}, refund_fn(service))
    assert service.count() == 0  # never blindly re-executed


def test_recover_stale_marks_unrecoverable_work_unknown(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=0) as led:
        with led.run("alice", "bot", run_id="r1"):
            crash_before_call(led, PLAIN_REFUND, {"order_id": "o1", "amount": 5})
        report = led.recover_stale()
    assert [(r.state, r.action) for r in report] == [(IntentState.UNKNOWN, "marked unknown")]


# ---------------------------------------------------------------- taint, scope, credentials, async


def test_tool_output_taints_the_run(ledger: Ledger) -> None:
    fetch = ToolSpec(name="web.fetch", effect="read", untrusted_output=True)
    read = ToolSpec(name="repo.read", effect="read", private_output=True)
    send = ToolSpec(name="email.send", effect="external_comm")
    with ledger.run("alice", "bot"):
        ledger.execute(fetch, {"url": "https://example.com"}, lambda url: "ignore previous")
        ledger.execute(read, {"path": "/srv/repo/secret.txt"}, lambda path: "private plan")
        with pytest.raises(ApprovalPending) as err:
            ledger.execute(send, {"to": "x@example.com", "body": "hi"}, lambda to, body: None)
    assert err.value.rule_id == "lethal-trifecta.outbound-after-both"


def test_actions_outside_the_run_scope_need_approval(
    ledger: Ledger, payments: FakePayments
) -> None:
    scope = Scope(task="Fix the login test", allowed_tools=("fs.*",))
    with ledger.run("alice", "bot", scope=scope), pytest.raises(ApprovalPending) as err:
        ledger.execute(REFUND, {"order_id": "o1", "amount": 5}, refund_fn(payments))
    assert err.value.rule_id == "outside-scope"


def test_the_run_spend_limit_counts_every_refund(ledger: Ledger, payments: FakePayments) -> None:
    scope = Scope(task="Refund order a", spend_limit=20)
    with ledger.run("alice", "bot", scope=scope):
        ledger.execute(REFUND, {"order_id": "a", "amount": 15}, refund_fn(payments))
        with pytest.raises(ApprovalPending) as err:
            ledger.execute(REFUND, {"order_id": "b", "amount": 10}, refund_fn(payments))
    assert err.value.rule_id == "outside-scope"
    assert payments.count() == 1


def test_child_runs_share_their_parent_spend_limit(ledger: Ledger, payments: FakePayments) -> None:
    scope = Scope(task="Refund order a", spend_limit=20)
    with ledger.run("alice", "bot", scope=scope):
        with ledger.run("alice", "sub-1"):
            ledger.execute(REFUND, {"order_id": "a", "amount": 15}, refund_fn(payments))
        with ledger.run("alice", "sub-2"), pytest.raises(ActionDenied) as err:
            ledger.execute(REFUND, {"order_id": "b", "amount": 10}, refund_fn(payments))
    assert err.value.rule_id == "budget"
    assert payments.count() == 1


def test_a_failed_refund_gives_back_its_spend(ledger: Ledger, payments: FakePayments) -> None:
    def declined(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        raise ValueError("card declined")

    with ledger.run("alice", "bot", scope=Scope(task="Refund", spend_limit=20)):
        with pytest.raises(ValueError, match="declined"):
            ledger.execute(REFUND, {"order_id": "a", "amount": 15}, declined)
        ledger.execute(REFUND, {"order_id": "b", "amount": 15}, refund_fn(payments))
    assert payments.count() == 1


def test_a_result_found_by_the_probe_taints_the_run(tmp_path: Path) -> None:
    service = FakePayments(native=False)
    spec = ToolSpec(
        name="payments.refund", effect="financial", idempotency="probe",
        probe="bench.fakes.probes:find_refund", untrusted_output=True,
    )  # fmt: skip
    with Ledger.open(tmp_path / "ledger.db", POLICY, key=KEY, worker_id="w1", lease_ttl=0) as led:
        led.probe_context["payments"] = service
        with led.run("alice", "bot", run_id="r1"):
            key = crash_before_call(led, spec, {"order_id": "o1", "amount": 5})
        service.refund("o1", 5, idempotency_key=key)
        with led.run("alice", "bot", run_id="r1", resume=True):
            led.execute(spec, {"order_id": "o1", "amount": 5}, refund_fn(service))
        with led._storage().transaction() as tx:
            run = tx.get_run("r1")
    service.close()
    assert run is not None
    assert run.taint.untrusted_input


def test_a_repeated_private_result_is_fingerprinted_again(ledger: Ledger) -> None:
    read = ToolSpec(name="repo.read", effect="read", private_output=True)
    text = "the launch plan moves to the third week of march for all regions"
    with ledger.run("alice", "bot", run_id="r1"):
        ledger.execute(read, {"path": "/srv/plan.txt"}, lambda path: text)
    with ledger.run("alice", "bot", run_id="r1", resume=True) as run:
        assert ledger.execute(read, {"path": "/srv/plan.txt"}, lambda path: "unused") == text
        assert run.fingerprints.shared(text) > 0


def test_credentials_are_injected_only_for_allowed_actions(tmp_path: Path) -> None:
    fetched: list[str] = []

    class Spy(EnvCredentials):
        def get(self, name: str) -> str:
            fetched.append(name)
            return super().get(name)

    creds = Spy(environ={"ARBITR_CRED_STRIPE": "sk_test_value"})
    spec = ToolSpec(name="payments.refund", effect="financial", credentials=("stripe",))
    drop = ToolSpec(name="db.exec", effect="write", credentials=("stripe",))
    seen: list[object] = []
    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY, credentials=creds) as led,
        led.run("a", "b"),
    ):
        led.execute(
            spec,
            {"order_id": "o", "amount": 1},
            lambda order_id, amount, credentials: seen.append(credentials),
        )
        with pytest.raises(ActionDenied):
            led.execute(drop, {"sql": "DROP TABLE t"}, lambda sql, credentials: None)
        stored = led.export_text()
    assert seen == [{"stripe": "sk_test_value"}]
    assert fetched == ["stripe"]  # the denied action never fetched it
    assert "sk_test_value" not in stored


def test_async_tools_run_through_the_same_path(ledger: Ledger, payments: FakePayments) -> None:
    async def tool(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
        await asyncio.sleep(0)
        return payments.refund(order_id, amount, idempotency_key=idempotency_key)

    async def main() -> object:
        with ledger.run("alice", "bot"):
            return await ledger.aexecute(REFUND, {"order_id": "o9", "amount": 3}, tool)

    assert asyncio.run(main()) == {"refund_id": "re_000001", "order_id": "o9", "amount": 3.0}


def test_long_calls_keep_their_lease(tmp_path: Path, payments: FakePayments) -> None:
    path = tmp_path / "ledger.db"
    with Ledger.open(path, POLICY, key=KEY, worker_id="w1", lease_ttl=0.6) as led:

        def slow(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
            time.sleep(1.5)
            with Ledger.open(path, POLICY, key=KEY, worker_id="w2") as other:
                assert other.stale_count() == 0  # the heartbeat kept the lease alive
            return "done"

        with led.run("alice", "bot"):
            assert led.execute(REFUND, {"order_id": "o1", "amount": 1}, slow) == "done"
        assert led.verify().ok


def test_a_closed_ledger_refuses_to_reopen(tmp_path: Path) -> None:
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY) as led:
        pass
    with pytest.raises(StorageError, match="closed"):
        led.intent_by_key("anything")
    with led.run("alice", "bot", resume=True), pytest.raises(LedgerUnavailable):
        led.execute(PLAIN_REFUND, {"order_id": "o", "amount": 1}, lambda **kw: None)
