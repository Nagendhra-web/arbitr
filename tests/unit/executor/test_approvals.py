"""Approvals end to end: bound to the arguments, expiring, quorum, links, webhook, analytics."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any, ClassVar

import pytest

from arbitr.approvals import WebhookNotifier, approval_stats
from arbitr.core.errors import ApprovalError, ApprovalPending, ApprovalRejected, UnknownOutcome
from arbitr.core.scope import Scope
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.executor import Ledger
from arbitr.policy.schema import load_policy

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"approval-flows!!" * 2
POLICY = load_policy("""
version: 1
default: { financial: allow, destructive: require_approval }
approval: { expires_after: 15m }
rules:
  - id: big-refunds
    when: { tool: payments.refund, args: [{ path: "$.amount", op: gt, value: 100 }] }
    then: require_approval
    reason: Refunds over 100 need a human.
  - id: refund-cap
    when: { tool: payments.refund }
    budget: { scope: [run], sum_path: "$.amount", limit: 1000 }
    then_exceeded: deny
    reason: Refund cap for the run.
  - id: payouts
    when: { tool: payments.payout }
    then: require_approval
    approvals: { required: 2, roles: [finance], separate_from_principal: true }
    reason: Payouts need two people from finance.
  - id: deletes
    when: { tool: files.delete }
    then: require_approval
    reason: Deleting files needs a human.
""")
REFUND = ToolSpec(name="payments.refund", effect="financial")
PAYOUT = ToolSpec(name="payments.payout", effect="financial")


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY, worker_id="w1") as led:
        yield led


def ask(ledger: Ledger, spec: ToolSpec, args: dict[str, object], calls: list[object]) -> object:
    return ledger.execute(spec, args, lambda **kw: calls.append(kw) or "done")


def pending_id(ledger: Ledger, spec: ToolSpec, args: dict[str, object]) -> str:
    with pytest.raises(ApprovalPending) as err:
        ledger.execute(spec, args, lambda **kw: None)
    return err.value.approval_id


def test_an_approved_action_runs_once_on_the_next_call(ledger: Ledger) -> None:
    calls: list[object] = []
    with ledger.run("alice", "bot", run_id="r1"):
        approval_id = pending_id(ledger, REFUND, {"order_id": "o1", "amount": 500})
        with pytest.raises(ApprovalPending):  # asking again before a decision changes nothing
            ask(ledger, REFUND, {"order_id": "o1", "amount": 500}, calls)
        ledger.approve(approval_id, approver="bob")
        assert ask(ledger, REFUND, {"order_id": "o1", "amount": 500}, calls) == "done"
        assert ask(ledger, REFUND, {"order_id": "o1", "amount": 500}, calls) == "done"
    assert len(calls) == 1
    assert ledger.verify().ok


def test_an_approval_for_one_set_of_arguments_cannot_authorize_another(ledger: Ledger) -> None:
    calls: list[object] = []
    with ledger.run("alice", "bot", run_id="r1"):
        first = pending_id(ledger, REFUND, {"order_id": "o1", "amount": 500})
        ledger.approve(first, approver="bob")
        with pytest.raises(ApprovalPending) as other:
            ask(ledger, REFUND, {"order_id": "o1", "amount": 450}, calls)
    assert other.value.approval_id != first
    assert calls == []


def test_an_expired_approval_is_rejected(tmp_path: Path) -> None:
    calls: list[object] = []
    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY, approval_ttl=0.05) as led,
        led.run("alice", "bot", run_id="r1"),
    ):
        approval_id = pending_id(led, REFUND, {"order_id": "o1", "amount": 500})
        time.sleep(0.1)
        with pytest.raises(ApprovalError, match="expired"):
            led.approve(approval_id, approver="bob")
        with pytest.raises(ApprovalRejected, match="expired"):
            ask(led, REFUND, {"order_id": "o1", "amount": 500}, calls)
    assert calls == []


def test_a_rejected_action_never_runs_and_gives_back_its_budget(ledger: Ledger) -> None:
    calls: list[object] = []
    with ledger.run("alice", "bot", run_id="r1"):
        approval_id = pending_id(ledger, REFUND, {"order_id": "o1", "amount": 900})
        ledger.reject(approval_id, approver="bob", note="wrong customer")
        with pytest.raises(ApprovalRejected):
            ask(ledger, REFUND, {"order_id": "o1", "amount": 900}, calls)
        # the 900 held for the rejected refund is free again under the 1000 cap
        second = pending_id(ledger, REFUND, {"order_id": "o2", "amount": 950})
        ledger.approve(second, approver="bob")
        assert ask(ledger, REFUND, {"order_id": "o2", "amount": 950}, calls) == "done"
    assert len(calls) == 1


def test_two_people_from_the_right_role_must_approve(ledger: Ledger) -> None:
    calls: list[object] = []
    args = {"account": "acct-9", "amount": 10_000}
    with ledger.run("alice", "bot", run_id="r1"):
        approval_id = pending_id(ledger, PAYOUT, args)
        with pytest.raises(ApprovalError, match="role"):
            ledger.approve(approval_id, approver="dave", roles=("support",))
        with pytest.raises(ApprovalError, match="own action"):
            ledger.approve(approval_id, approver="alice", roles=("finance",))
        assert ledger.approve(approval_id, approver="bob", roles=("finance",)).status == "pending"
        with pytest.raises(ApprovalPending):
            ask(ledger, PAYOUT, args, calls)
        assert (
            ledger.approve(approval_id, approver="carol", roles=("finance",)).status == "approved"
        )
        assert ask(ledger, PAYOUT, args, calls) == "done"
    assert len(calls) == 1


def test_signed_links_approve_only_their_own_intent(ledger: Ledger) -> None:
    calls: list[object] = []
    with ledger.run("alice", "bot", run_id="r1"):
        first = pending_id(ledger, REFUND, {"order_id": "o1", "amount": 500})
        second = pending_id(ledger, REFUND, {"order_id": "o2", "amount": 400})
        links = ledger.approval_links(first, approver="bob", base_url="https://approve.example")
        token = links["approve"].split("token=", 1)[1]
        forged = token.replace(first, second, 1)
        with pytest.raises(ApprovalError, match="signature"):
            ledger.decide_by_link(forged)
        assert ledger.decide_by_link(token).status == "approved"
        with pytest.raises(ApprovalError, match="already approved"):
            ledger.decide_by_link(token)  # a link works once
        assert ask(ledger, REFUND, {"order_id": "o1", "amount": 500}, calls) == "done"
        with pytest.raises(ApprovalPending):
            ask(ledger, REFUND, {"order_id": "o2", "amount": 400}, calls)
    assert len(calls) == 1


def test_a_link_signed_with_another_key_is_refused(ledger: Ledger, tmp_path: Path) -> None:
    with ledger.run("alice", "bot", run_id="r1"):
        approval_id = pending_id(ledger, REFUND, {"order_id": "o1", "amount": 500})
    with Ledger.open(
        tmp_path / "other.db", POLICY, key=b"another-key-of-32-bytes-length!!"
    ) as other:
        with other.run("alice", "bot", run_id="r1"):
            other_id = pending_id(other, REFUND, {"order_id": "o1", "amount": 500})
        bad = other.approval_links(other_id, approver="bob", base_url="https://x")["approve"]
    with pytest.raises(ApprovalError):
        ledger.decide_by_link(bad.split("token=", 1)[1].replace(other_id, approval_id))


class _Hook(BaseHTTPRequestHandler):
    received: ClassVar[list[dict[str, Any]]] = []

    def do_POST(self) -> None:
        length = int(self.headers["Content-Length"])
        _Hook.received.append(json.loads(self.rfile.read(length)))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def webhook() -> Iterator[str]:
    _Hook.received = []
    server = HTTPServer(("127.0.0.1", 0), _Hook)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/hook"
    server.shutdown()
    server.server_close()


def test_the_webhook_gets_a_readable_card_with_signed_links(tmp_path: Path, webhook: str) -> None:
    notifier = WebhookNotifier(webhook, link_base_url="https://approve.example",
                               approvers={"bob": ("finance",)})  # fmt: skip
    task = "Refund the customer for order o1"
    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY, notifier=notifier) as led,
        led.run("alice", "bot", run_id="r1", scope=Scope(task=task)),
    ):
        approval_id = pending_id(led, REFUND, {"order_id": "o1", "amount": 500, "api_key": "x"})
    (message,) = _Hook.received
    card = message["card"]
    assert card["approval_id"] == approval_id
    assert card["tool"] == "payments.refund"
    assert card["rule"] == "big-refunds"
    assert card["reason"] == "Refunds over 100 need a human."
    assert card["task"] == task
    assert "Refunds over 100 need a human." in card["text"]
    assert message["links"]["bob"]["approve"].startswith("https://approve.example")
    assert '"x"' not in json.dumps(card)  # the api_key value is redacted


def test_a_failing_webhook_does_not_break_the_call(tmp_path: Path) -> None:
    notifier = WebhookNotifier("http://127.0.0.1:9/nothing", link_base_url="https://x", timeout=0.5)
    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY, notifier=notifier) as led,
        led.run("alice", "bot"),
        pytest.raises(ApprovalPending),
    ):
        led.execute(REFUND, {"order_id": "o1", "amount": 500}, lambda **kw: None)


def test_an_unknown_outcome_is_retried_once_a_human_approves(tmp_path: Path) -> None:
    calls: list[object] = []
    spec = ToolSpec(name="payments.refund", effect="financial")
    args = {"order_id": "o1", "amount": 5}

    def times_out(**kwargs: object) -> object:
        calls.append(kwargs)
        raise TimeoutError("no response")

    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY) as led,
        led.run("alice", "bot", run_id="r1") as run,
    ):
        with pytest.raises(UnknownOutcome):
            led.execute(spec, args, times_out)
        with pytest.raises(UnknownOutcome, match="human"):
            led.execute(spec, args, times_out)
        row = led.intent_by_key(run.last_idempotency_key)
        assert row is not None
        (request,) = [a for a in led.approvals() if a.intent_id == row.intent_id]
        led.approve(request.approval_id, approver="bob", note="checked: it did not run")
        assert led.execute(spec, args, lambda **kw: "ok") == "ok"
    assert len(calls) == 1


def test_rejecting_an_unknown_outcome_marks_it_failed_for_good(tmp_path: Path) -> None:
    spec = ToolSpec(name="payments.refund", effect="financial")
    args = {"order_id": "o1", "amount": 5}

    def times_out(**kwargs: object) -> object:
        raise TimeoutError("no response")

    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY) as led,
        led.run("alice", "bot", run_id="r1"),
    ):
        with pytest.raises(UnknownOutcome):
            led.execute(spec, args, times_out)
        with pytest.raises(UnknownOutcome):
            led.execute(spec, args, times_out)
        (request,) = led.approvals(status="pending")
        led.reject(request.approval_id, approver="bob", note="it ran, do not repeat")
        with pytest.raises(UnknownOutcome, match="will not run again"):
            led.execute(spec, args, lambda **kw: "never")
        assert led.intent(request.intent_id).state == IntentState.FAILED  # type: ignore[union-attr]


def test_the_card_explains_the_action_without_secrets(ledger: Ledger) -> None:
    secret = "sk_" + "live_" + "abcdefghijklmnop"  # built from pieces for secret scanners
    with ledger.run("alice", "bot", run_id="r1", scope=Scope(task="Refund o1")):
        approval_id = pending_id(ledger, REFUND, {"order_id": "o1", "amount": 500, "token": secret})
    card = ledger.approval_card(approval_id)
    assert card["tool"] == "payments.refund"
    assert card["effect"] == "financial"
    assert card["args"]["amount"] == 500
    assert secret not in json.dumps(card)
    assert card["text"].startswith("payments.refund")


def test_rubber_stamped_rules_are_flagged(ledger: Ledger) -> None:
    delete = ToolSpec(name="files.delete", effect="write")
    with ledger.run("alice", "bot", run_id="r1"):
        for i in range(25):
            approval_id = pending_id(ledger, delete, {"path": f"/srv/tmp/{i}.log"})
            ledger.approve(approval_id, approver="bob")
        for i in range(4):
            approval_id = pending_id(ledger, PAYOUT, {"account": f"a{i}", "amount": 1})
            ledger.reject(approval_id, approver="bob", roles=("finance",))
    stats = {s.rule_id: s for s in approval_stats(ledger)}
    assert stats["deletes"].requested == 25
    assert stats["deletes"].approval_rate == 1.0
    assert stats["deletes"].rubber_stamp
    assert "allow rule" in stats["deletes"].suggestion
    assert not stats["payouts"].rubber_stamp
    assert stats["payouts"].approval_rate == 0.0


# ---------------------------------------------------------------- security follow-ups

STRICT = load_policy("""
version: 1
default: { financial: allow }
approval: { required: 2, roles: [sre], separate_from_principal: true }
""")


def test_an_unknown_outcome_needs_the_same_approvers_as_any_approval(tmp_path: Path) -> None:
    spec = ToolSpec(name="payments.refund", effect="financial")
    args = {"order_id": "o1", "amount": 5}

    def times_out(**kwargs: object) -> object:
        raise TimeoutError("no response")

    with (
        Ledger.open(tmp_path / "l.db", STRICT, key=KEY) as led,
        led.run("alice", "bot", run_id="r1"),
    ):
        for _ in range(2):
            with pytest.raises(UnknownOutcome):
                led.execute(spec, args, times_out)
        (request,) = led.approvals(status="pending")
        assert (request.required, request.allowed_roles(), request.separate_from) == (
            2,
            ("sre",),
            "alice",
        )
        with pytest.raises(ApprovalError, match="own action"):
            led.approve(request.approval_id, approver="alice", roles=("sre",))
        assert led.approve(request.approval_id, approver="bob", roles=("sre",)).status == "pending"
        with pytest.raises(UnknownOutcome, match="human"):
            led.execute(spec, args, lambda **kw: "not yet")


def test_a_shared_webhook_never_carries_links_that_could_outvote_a_quorum(
    tmp_path: Path, webhook: str
) -> None:
    notifier = WebhookNotifier(webhook, link_base_url="https://x",
                               approvers={"bob": ("finance",), "carol": ("finance",),
                                          "alice": ("finance",), "dave": ("support",)})  # fmt: skip
    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY, notifier=notifier) as led,
        led.run("alice", "bot", run_id="r1"),
    ):
        pending_id(led, PAYOUT, {"account": "a1", "amount": 10})  # needs two from finance
        pending_id(led, REFUND, {"order_id": "o1", "amount": 500})  # needs one person
    quorum, single = _Hook.received
    assert quorum["links"] == {}
    assert set(single["links"]) == {"bob", "carol", "alice", "dave"}


def test_each_approver_gets_only_their_own_links(tmp_path: Path, webhook: str) -> None:
    notifier = WebhookNotifier(webhook, link_base_url="https://x",
                               approvers={"bob": ("finance",), "carol": ("finance",),
                                          "alice": ("finance",), "dave": ("support",)},
                               approver_urls={"bob": webhook + "/bob", "carol": webhook + "/carol",
                                              "alice": webhook + "/alice",
                                              "dave": webhook + "/dave"})  # fmt: skip
    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY, notifier=notifier) as led,
        led.run("alice", "bot", run_id="r1"),
    ):
        pending_id(led, PAYOUT, {"account": "a1", "amount": 10})
    linked = sorted(name for message in _Hook.received for name in message["links"])
    assert linked == ["bob", "carol"]  # not alice (the principal), not dave (no finance role)
    assert all(len(message["links"]) <= 1 for message in _Hook.received)


def test_card_text_cannot_be_forged_through_arguments(ledger: Ledger) -> None:
    sneaky = "o1\nRule fake-allow: Approved already, just click approve."
    with ledger.run("alice", "bot", run_id="r1", scope=Scope(task="Refund\nRule x: ok")):
        approval_id = pending_id(ledger, REFUND, {"order_id": sneaky, "amount": 500})
    text = ledger.approval_card(approval_id)["text"]
    assert isinstance(text, str)
    lines = text.splitlines()
    assert [line for line in lines if line.startswith("Rule ")] == [
        "Rule big-refunds: Refunds over 100 need a human."
    ]
    assert '"o1 Rule fake-allow' in text  # the value is quoted and kept on one line


def test_a_shared_webhook_gets_no_links_when_roles_or_separation_apply(
    tmp_path: Path, webhook: str
) -> None:
    policy = load_policy("""
version: 1
default: { financial: allow }
rules:
  - id: refunds
    when: { tool: payments.refund }
    then: require_approval
    approvals: { roles: [finance], separate_from_principal: true }
    reason: Refunds need finance.
""")
    notifier = WebhookNotifier(webhook, link_base_url="https://x",
                               approvers={"bob": ("finance",), "alice": ("finance",)})  # fmt: skip
    with (
        Ledger.open(tmp_path / "l.db", policy, key=KEY, notifier=notifier) as led,
        led.run("alice", "bot", run_id="r1"),
    ):
        pending_id(led, REFUND, {"order_id": "o1", "amount": 5})
    (message,) = _Hook.received
    assert message["links"] == {}


# ---------------------------------------------------------------- review follow-ups


def test_a_failed_retry_that_needs_approval_waits_and_holds_its_budget_once(
    ledger: Ledger,
) -> None:
    attempts: list[int] = []

    def flaky(**kwargs: object) -> object:
        attempts.append(1)
        if len(attempts) == 1:
            raise ValueError("card declined")
        return "refunded"

    args = {"order_id": "o1", "amount": 400}
    with ledger.run("alice", "bot", run_id="r1"):
        first = pending_id(ledger, REFUND, args)
        ledger.approve(first, approver="bob")
        with pytest.raises(ValueError, match="declined"):
            ledger.execute(REFUND, args, flaky)
        second = pending_id(ledger, REFUND, args)  # the retry needs approval again
        assert pending_id(ledger, REFUND, args) == second  # and waits; no new request
        with ledger._storage().transaction() as tx:
            assert tx.budget_counters(["rule:refund-cap|run:r1"]) == {
                "rule:refund-cap|run:r1": 400.0
            }
        ledger.approve(second, approver="bob")
        assert ledger.execute(REFUND, args, flaky) == "refunded"
    assert len(attempts) == 2
    assert ledger.verify().ok


def test_an_approval_goes_stale_when_the_action_does_not_run_in_time(tmp_path: Path) -> None:
    calls: list[object] = []
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY, approval_ttl=0.2) as led:
        with led.run("alice", "bot", run_id="r1"):
            approval_id = pending_id(led, REFUND, {"order_id": "o1", "amount": 500})
            led.approve(approval_id, approver="bob")
            other = pending_id(led, REFUND, {"order_id": "o2", "amount": 300})
            led.approve(other, approver="bob")
            time.sleep(0.3)
            with pytest.raises(ApprovalRejected, match="stale"):
                ask(led, REFUND, {"order_id": "o1", "amount": 500}, calls)
            swept = led.expire_approvals()  # what `arbitr recover` does
            assert [a.approval_id for a in swept] == [other]
            with led._storage().transaction() as tx:
                assert tx.budget_counters(["rule:refund-cap|run:r1"]) == {
                    "rule:refund-cap|run:r1": 0.0
                }
        assert led.verify().ok
    assert calls == []


def test_the_unknown_outcome_card_shows_the_action(tmp_path: Path) -> None:
    spec = ToolSpec(name="payments.refund", effect="financial")
    args = {"order_id": "o1", "amount": 5}

    def times_out(**kwargs: object) -> object:
        raise TimeoutError("no response")

    with (
        Ledger.open(tmp_path / "l.db", POLICY, key=KEY) as led,
        led.run("alice", "bot", run_id="r1", scope=Scope(task="Refund order o1")),
    ):
        for _ in range(2):
            with pytest.raises(UnknownOutcome):
                led.execute(spec, args, times_out)
        (request,) = led.approvals(status="pending")
        card = led.approval_card(request.approval_id)
    assert card["args"] == {"order_id": "o1", "amount": 5}
    assert card["task"] == "Refund order o1"
    assert card["rule"] == "on-unknown"


def test_webhooks_need_https_except_on_this_machine() -> None:
    with pytest.raises(ApprovalError, match="https"):
        WebhookNotifier("http://hooks.example.com/x", link_base_url="https://x")
    with pytest.raises(ApprovalError, match="https"):
        WebhookNotifier("https://hooks.example.com/x", link_base_url="https://x",
                        approver_urls={"bob": "http://bob.example.com"})  # fmt: skip
    WebhookNotifier("http://127.0.0.1:8080/x", link_base_url="https://x")
    WebhookNotifier("http://localhost/x", link_base_url="https://x")


def test_the_principal_may_reject_their_own_action(ledger: Ledger) -> None:
    with ledger.run("alice", "bot", run_id="r1"):
        approval_id = pending_id(ledger, PAYOUT, {"account": "a1", "amount": 10})
    assert ledger.reject(approval_id, approver="alice", roles=("finance",)).status == "rejected"


def test_a_cut_argument_is_flagged_and_kept_in_full(ledger: Ledger) -> None:
    hidden = "x" * 300 + " AND the real target"
    with ledger.run("alice", "bot", run_id="r1"):
        approval_id = pending_id(ledger, REFUND, {"order_id": hidden, "amount": 500})
    card = ledger.approval_card(approval_id)
    assert card["truncated"] is True
    assert card["args_full"]["order_id"] == hidden
    assert "AND the real target" in card["args"]["order_id"]  # the tail is shown
    assert "CUT" in card["text"]
