"""Terraform previews: how many resources a plan destroys, and how many are critical.

The plan is the JSON that ``terraform show -json <planfile>`` prints. It comes
from the call's arguments (``plan_json``, ``terraform_plan`` or ``plan``, as
an object or as text) or from the preview context (``terraform_plan``). This
previewer never runs terraform: producing the plan is the caller's job.

A resource is destroyed when its planned actions include ``delete``; a
replacement (``delete`` and ``create``) counts as destroyed and as replaced.
A destroyed resource is critical when its current tags (``tags``,
``tags_all`` or ``labels``) match an entry of ``critical_tags`` in the
context: ``"critical"`` matches any value of that tag, ``"env=prod"`` only
that value.

Example:
    >>> plan = {"resource_changes": [{"change": {"actions": ["delete"], "before": {}}}]}
    >>> preview_terraform({"plan": plan}, {}).summary
    'terraform would destroy 1 resource'
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Final

from arbitr.preview.base import Preview, plural

PLAN: Final = "terraform_plan"
CRITICAL_TAGS: Final = "critical_tags"

_PLAN_KEYS: Final = ("plan_json", "terraform_plan", "plan")
_TAG_FIELDS: Final = ("tags", "tags_all", "labels")


class Unreadable(Exception):  # noqa: N818 - a reason, not an error the caller handles
    """The plan is not the JSON that terraform show prints."""


def _plan(args: Mapping[str, object], context: Mapping[str, object]) -> Mapping[str, object]:
    raw = next((args[k] for k in _PLAN_KEYS if k in args), context.get(PLAN))
    if raw is None:
        raise Unreadable("no terraform plan JSON in the arguments or the preview context")
    if isinstance(raw, str | bytes):
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            raise Unreadable("the terraform plan is not valid JSON") from exc
    if not isinstance(raw, Mapping):
        raise Unreadable("the terraform plan is not a JSON object")
    return raw


def _rules(context: Mapping[str, object]) -> list[tuple[str, str | None]]:
    raw = context.get(CRITICAL_TAGS)
    if not isinstance(raw, list | tuple):
        return []
    rules: list[tuple[str, str | None]] = []
    for entry in raw:
        if isinstance(entry, str):
            key, sep, value = entry.partition("=")
            rules.append((key, value if sep else None))
    return rules


def _critical(before: object, rules: list[tuple[str, str | None]]) -> bool:
    if not isinstance(before, Mapping):
        return False
    for name in _TAG_FIELDS:
        tags = before.get(name)
        if not isinstance(tags, Mapping):
            continue
        for key, value in rules:
            if key in tags and (value is None or str(tags[key]) == value):
                return True
    return False


def _actions(change: object) -> tuple[Mapping[str, object], list[str]]:
    if not isinstance(change, Mapping):
        raise Unreadable("a resource change is not an object")
    body = change.get("change")
    actions = body.get("actions") if isinstance(body, Mapping) else None
    if not isinstance(body, Mapping) or not isinstance(actions, list):
        raise Unreadable("a resource change has no list of actions")
    return body, [str(a) for a in actions]


def _count(plan: Mapping[str, object], rules: list[tuple[str, str | None]]) -> dict[str, int]:
    changes = plan.get("resource_changes") or []
    if not isinstance(changes, list):
        raise Unreadable("resource_changes is not a list")
    counts = dict.fromkeys(
        ("resources_destroyed", "resources_replaced", "resources_created", "resources_updated",
         "critical"), 0,
    )  # fmt: skip
    for change in changes:
        body, actions = _actions(change)
        if "delete" in actions:
            counts["resources_destroyed"] += 1
            counts["resources_replaced"] += "create" in actions
            counts["critical"] += _critical(body.get("before"), rules)
        elif "create" in actions:
            counts["resources_created"] += 1
        elif "update" in actions:
            counts["resources_updated"] += 1
    return counts


def preview_terraform(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
    """Count what a terraform plan destroys, replaces, creates and updates."""
    try:
        counts = _count(_plan(args, context), _rules(context))
    except Unreadable as exc:
        return Preview.failed(f"No preview: {exc}")
    summary = f"terraform would destroy {plural(counts['resources_destroyed'], 'resource')}"
    if counts["resources_replaced"]:
        summary += f" ({counts['resources_replaced']:,} replaced)"
    if counts["critical"]:
        summary += f", {counts['critical']:,} critical"
    return Preview(summary, dict(counts))
