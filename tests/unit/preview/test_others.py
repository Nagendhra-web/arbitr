"""Terraform, email and payment previews: pure counts over the arguments."""

from __future__ import annotations

import json

import pytest

from arbitr.preview.email import INTERNAL_DOMAINS, preview_email
from arbitr.preview.payments import preview_payments
from arbitr.preview.terraform import CRITICAL_TAGS, PLAN, preview_terraform


def _change(address: str, actions: list[str], tags: dict[str, str] | None = None) -> object:
    before = None if actions == ["create"] else {"id": address, "tags": tags or {}}
    return {"address": address, "type": "aws_s3_bucket", "change": {"actions": actions,
            "before": before}}  # fmt: skip


PLAN_JSON = {
    "format_version": "1.2",
    "resource_changes": [
        _change("aws_s3_bucket.logs", ["delete"], {"env": "dev"}),
        _change("aws_s3_bucket.data", ["delete"], {"env": "prod", "critical": "true"}),
        _change("aws_db_instance.main", ["delete", "create"], {"env": "prod"}),
        _change("aws_s3_bucket.new", ["create"]),
        _change("aws_iam_role.app", ["update"]),
        _change("aws_iam_role.same", ["no-op"]),
        {"address": "google_bucket.x", "change": {"actions": ["delete"],
         "before": {"labels": {"tier": "critical"}}}},
    ],
}  # fmt: skip


def test_terraform_counts_destroyed_and_critical_resources() -> None:
    context = {CRITICAL_TAGS: ["critical", "env=prod", "tier=critical"]}
    preview = preview_terraform({"plan_json": PLAN_JSON}, context)
    assert preview.ok, preview
    assert preview.facts == {
        "resources_destroyed": 4,
        "resources_replaced": 1,
        "resources_created": 1,
        "resources_updated": 1,
        "critical": 3,
    }
    assert preview.summary == "terraform would destroy 4 resources (1 replaced), 3 critical"


def test_terraform_reads_text_from_the_arguments_or_the_context() -> None:
    text = json.dumps(PLAN_JSON)
    assert preview_terraform({"plan": text}, {}).facts["resources_destroyed"] == 4
    assert preview_terraform({}, {PLAN: text}).facts["critical"] == 0
    assert preview_terraform({"plan": text.encode()}, {}).ok
    empty = preview_terraform({"plan": {"resource_changes": []}}, {})
    assert empty.summary == "terraform would destroy 0 resources"


@pytest.mark.parametrize(
    "plan",
    [
        None,
        "not json",
        [1],
        {"resource_changes": "x"},
        {"resource_changes": [5]},
        {"resource_changes": [{"change": {"actions": "delete"}}]},
        {"resource_changes": [{"change": None}]},
    ],
)
def test_terraform_refuses_plans_it_cannot_read(plan: object) -> None:
    args = {} if plan is None else {"plan": plan}
    assert not preview_terraform(args, {}).ok


def test_terraform_ignores_bad_critical_settings() -> None:
    preview = preview_terraform({"plan": PLAN_JSON}, {CRITICAL_TAGS: "critical"})
    assert preview.facts["critical"] == 0
    preview = preview_terraform({"plan": PLAN_JSON}, {CRITICAL_TAGS: [5, "critical"]})
    assert preview.facts["critical"] == 1


def test_email_counts_external_recipients() -> None:
    args = {
        "to": "Ann <ann@corp.example>, bob@partner.example",
        "cc": ["carol@eng.corp.example", "ANN@corp.example"],
        "bcc": "dave@evilcorp.example",
    }
    preview = preview_email(args, {INTERNAL_DOMAINS: ["corp.example"]})
    assert preview.ok, preview
    assert preview.facts == {"recipients": 4, "external_recipients": 2,
                             "internal_recipients": 2, "domains": 4}  # fmt: skip
    assert preview.summary == "email to 4 recipients, 2 external"


def test_email_without_internal_domains_counts_everyone_as_external() -> None:
    preview = preview_email({"to": "a@x.example"}, {INTERNAL_DOMAINS: "x.example"})
    assert preview.facts["external_recipients"] == 1
    assert preview.summary == "email to 1 recipient, 1 external"


def test_email_with_unparsed_recipients_fails_safe() -> None:
    preview = preview_email({"to": "a@x.example, someone"}, {})
    assert not preview.ok
    assert preview.facts["recipients"] == 1
    assert "could not be parsed" in preview.summary
    assert not preview_email({"subject": "hi"}, {}).ok


def test_payments_total_every_amount() -> None:
    single = preview_payments({"amount": 250, "currency": "usd"}, {})
    assert single.facts == {"amount_total": 250.0, "payments": 1, "currency": "USD"}
    assert single.summary == "1 payment totalling 250.00 USD"
    batch = preview_payments(
        {"payouts": [{"amount": 10.5}, {"amount": 20, "meta": {"amount": 1}}]}, {}
    )
    assert batch.facts == {"amount_total": 31.5, "payments": 3}
    assert batch.summary == "3 payments totalling 31.50"


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"amount": "100"},
        {"amount": True},
        {"amount": -5},
        {"amount": float("inf")},
        {"items": [{"amount": 1, "currency": "usd"}, {"amount": 2, "currency": "eur"}]},
    ],
)
def test_payments_refuse_amounts_they_cannot_total(args: dict[str, object]) -> None:
    assert not preview_payments(args, {}).ok


def test_payments_stop_on_deep_or_huge_arguments() -> None:
    deep: dict[str, object] = {"amount": 1}
    for _ in range(100):
        deep = {"x": deep}
    assert not preview_payments(deep, {}).ok
    wide = {"items": [{"amount": 1}] * 20_000}
    assert not preview_payments(wide, {}).ok
