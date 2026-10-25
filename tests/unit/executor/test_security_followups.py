"""Follow-ups from a security review: bool amounts, retries and delays, recipient backstops."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import ActionScheduled, ApprovalPending
from arbitr.core.scope import Scope
from arbitr.core.spec import ToolSpec
from arbitr.executor import Ledger
from arbitr.policy.schema import load_policy

if TYPE_CHECKING:
    from pathlib import Path

KEY = b"security-follow!" * 2
ALLOW = load_policy("version: 1\ndefault: { financial: allow, external_comm: allow }\n")
DELAYED = load_policy("""
version: 1
default: { financial: allow }
rules:
  - id: hold-refunds
    when: { tool: payments.refund }
    then: delay 1s
    reason: Refunds wait a moment.
""")
REFUND = ToolSpec(name="payments.refund", effect="financial")


def declined(**kwargs: object) -> object:
    raise ValueError("card declined")


def test_a_bool_amount_cannot_slip_past_the_spend_limit(tmp_path: Path) -> None:
    calls: list[object] = []
    with (
        Ledger.open(tmp_path / "l.db", ALLOW, key=KEY) as led,
        led.run("alice", "bot", scope=Scope(task="Refund", spend_limit=20)),
        pytest.raises(ApprovalPending) as err,
    ):
        led.execute(REFUND, {"order_id": "o1", "amount": True}, lambda **kw: calls.append(kw))
    assert err.value.rule_id == "outside-scope"
    assert calls == []


def test_a_retry_cannot_skip_a_cancel_window_it_never_had(tmp_path: Path) -> None:
    """Allowed and failed under one policy, retried after a delay rule was added."""
    path = tmp_path / "l.db"
    args = {"order_id": "o1", "amount": 5}
    with (
        Ledger.open(path, ALLOW, key=KEY) as led,
        led.run("alice", "bot", run_id="r1"),
        pytest.raises(ValueError, match="declined"),
    ):
        led.execute(REFUND, args, declined)
    calls: list[int] = []
    with (
        Ledger.open(path, DELAYED, key=KEY) as led,
        led.run("alice", "bot", run_id="r1", resume=True),
        pytest.raises(ApprovalPending) as err,
    ):
        led.execute(REFUND, args, lambda **kw: calls.append(1))
    assert err.value.rule_id == "hold-refunds"
    assert calls == []


def test_a_scheduled_action_that_failed_retries_without_a_second_window(tmp_path: Path) -> None:
    args = {"order_id": "o1", "amount": 5}
    with Ledger.open(tmp_path / "l.db", DELAYED, key=KEY) as led:
        with led.run("alice", "bot", run_id="r1"), pytest.raises(ActionScheduled):
            led.execute(REFUND, args, declined)
        time.sleep(1.05)
        (result,) = led.run_due({REFUND.name: (REFUND, declined)})
        assert result.action == "failed: ValueError"
        with led.run("alice", "bot", run_id="r1", resume=True):
            assert led.execute(REFUND, args, lambda **kw: "ok") == "ok"


@pytest.mark.parametrize("field", ["to", "cc", "bcc"])
def test_long_recipient_lists_need_approval_even_with_a_custom_extractor(
    tmp_path: Path, field: str
) -> None:
    policy = load_policy(
        "version: 1\ninclude: [email-and-messaging]\ndefault: { external_comm: allow }\n"
    )
    mail = ToolSpec(
        name="mail.send", effect="external_comm", resource_extractor="custom_extractors:tables"
    )
    recipients = [f"u{i}@example.com" for i in range(51)]
    with (
        Ledger.open(tmp_path / "l.db", policy, key=KEY) as led,
        led.run("alice", "bot"),
        pytest.raises(ApprovalPending) as err,
    ):
        led.execute(mail, {field: recipients, "body": "news"}, lambda **kw: None)
    assert err.value.rule_id == f"email-and-messaging.many-{field}-list"
