r"""``arbitr policy lint``: warnings about rules that cannot do what they say.

- ``never-matches``: conditions that contradict each other, such as a tool
  that does not match the rule's own tool glob, or an empty list.
- ``unknown-resource``, ``unknown-tag``, ``unknown-finding``: names the policy
  never defines, usually typos. A rule waiting on a misspelled tag never fires.
- ``shadowed``: an earlier or stricter rule matches everything this rule
  matches, so this rule never decides anything.
- ``destructive-without-rule``: a registered destructive tool that no rule
  mentions, so only the default protects it.
- ``permissive-default``: destructive actions are allowed by default.

Example:
    >>> from arbitr.policy.schema import load_policy
    >>> [w.code for w in lint_policy(load_policy("version: 1\ndefault: {destructive: allow}"))]
    ['permissive-default']
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from arbitr.core.redact import DETECTORS
from arbitr.policy.engine import RANK
from arbitr.resources.registry import UNRESOLVED_PATH

if TYPE_CHECKING:
    from collections.abc import Iterable

    from arbitr.core.spec import ToolSpec
    from arbitr.policy.schema import Policy, Rule, When

SYSTEM_TAGS: Final = frozenset({UNRESOLVED_PATH})
FINDING_CATEGORIES: Final = frozenset({"secret", "pii", "private_content", "unscannable"})
KNOWN_FINDINGS: Final = (
    FINDING_CATEGORIES
    | {f"secret:{name}" for name, _ in DETECTORS}
    | {"unscannable:private_content"}
)


@dataclass(frozen=True)
class LintWarning:
    """One problem in a policy."""

    code: str
    rule_id: str | None
    message: str

    def to_dict(self) -> dict[str, str | None]:
        """The machine-readable form."""
        return {"code": self.code, "rule_id": self.rule_id, "message": self.message}


def _never_matches(when: When) -> str | None:
    if (
        when.tool is not None
        and when.tool_glob is not None
        and not fnmatch.fnmatchcase(when.tool, when.tool_glob)
    ):
        return f"tool {when.tool} does not match tool_glob {when.tool_glob}"
    if when.effect is not None and when.effect_in is not None and when.effect not in when.effect_in:
        return f"effect {when.effect} is not in effect_in"
    for name in ("effect_in", "principal_in", "agent_in", "resource_ids_any", "resource_tags_any"):
        if getattr(when, name) == ():
            return f"{name} is an empty list"
    return None


def _finding_known(name: str) -> bool:
    category = name.split(":", 1)[0]
    if name in KNOWN_FINDINGS:
        return True
    return category == "pii" and ":" in name  # personal data detectors are plugins


def _unknown_names(rule: Rule, policy: Policy) -> list[LintWarning]:
    when = rule.when
    warnings = []
    ids = {r.id for r in policy.resources}
    tags = {t for r in policy.resources for t in r.tags} | SYSTEM_TAGS
    missing_ids = sorted(set(when.resource_ids_any or ()) - ids)
    if missing_ids:
        message = f"resource ids not defined under 'resources': {', '.join(missing_ids)}"
        warnings.append(LintWarning("unknown-resource", rule.id, message))
    missing_tags = sorted(
        (set(when.resource_tags_any or ()) | set(when.resource_tags_all or ())) - tags
    )
    if missing_tags:
        message = f"no resource has these tags: {', '.join(missing_tags)}"
        warnings.append(LintWarning("unknown-tag", rule.id, message))
    unknown = sorted(n for n in when.outbound_findings_any or () if not _finding_known(n))
    if unknown:
        message = f"unknown outbound finding names: {', '.join(unknown)}"
        warnings.append(LintWarning("unknown-finding", rule.id, message))
    return warnings


def _covers(general: When, specific: When) -> bool:
    """Whether ``general`` matches every input that ``specific`` matches."""
    for name in type(general).model_fields:
        value = getattr(general, name)
        if value is None or value == getattr(specific, name):
            continue
        if (
            name == "tool_glob"
            and specific.tool is not None
            and fnmatch.fnmatchcase(specific.tool, value)
        ):
            continue
        if name == "effect_in" and specific.effect is not None and specific.effect in value:
            continue
        return False
    return True


def _shadowed(rules: tuple[Rule, ...]) -> list[LintWarning]:
    warnings = []
    for j, later in enumerate(rules):
        if later.budget is not None or later.then is None:
            continue
        for i, other in enumerate(rules):
            if i == j or other.budget is not None or other.then is None:
                continue
            if _never_matches(other.when) is not None:
                continue
            if later.always_enforce and not other.always_enforce:
                continue
            stricter = RANK[other.then] > RANK[later.then]
            first_equal = RANK[other.then] == RANK[later.then] and i < j
            if (stricter or first_equal) and _covers(other.when, later.when):
                message = f"rule {other.id} matches everything this rule matches and wins"
                warnings.append(LintWarning("shadowed", later.id, message))
                break
    return warnings


def _mentions_tool(when: When, tool: ToolSpec) -> bool:
    if when.tool is not None:
        return when.tool == tool.name
    if when.tool_glob is not None:
        return fnmatch.fnmatchcase(tool.name, when.tool_glob)
    if when.effect is not None:
        return when.effect == "destructive"
    if when.effect_in is not None:
        return "destructive" in when.effect_in
    return False


def lint_policy(policy: Policy, tools: Iterable[ToolSpec] = ()) -> list[LintWarning]:
    """Every warning for the policy, rule by rule in policy order, then global ones."""
    warnings: list[LintWarning] = []
    for rule in policy.rules:
        reason = _never_matches(rule.when)
        if reason is not None:
            warnings.append(LintWarning("never-matches", rule.id, f"can never match: {reason}"))
        warnings.extend(_unknown_names(rule, policy))
    shadowed = {w.rule_id: w for w in _shadowed(policy.rules)}
    ordered = [shadowed[r.id] for r in policy.rules if r.id in shadowed]
    warnings.extend(ordered)
    unruled = sorted(
        tool.name
        for tool in tools
        if tool.effect == "destructive"
        and not any(_mentions_tool(rule.when, tool) for rule in policy.rules)
    )
    if unruled:
        message = f"destructive tools with no rule (only the default applies): {', '.join(unruled)}"
        warnings.append(LintWarning("destructive-without-rule", None, message))
    if policy.default.destructive == "allow":
        message = "destructive actions are allowed by default; require_approval is safer"
        warnings.append(LintWarning("permissive-default", None, message))
    return warnings
