"""Run scope manifests: what a run was asked to do.

A run can declare its scope when it starts: the tools it may call (globs),
the resource tags it may touch, the most severe effect it may have, how much
it may spend, and the user's original request. An action outside the scope is
held for approval by default (or denied, by policy), and the request text is
shown next to it so a human can judge the mismatch quickly.

A sub-agent's scope must sit inside its parent's.

Example:
    >>> scope = Scope(task="Fix the failing test", allowed_tools=("fs.*",), max_effect="write")
    >>> check_scope(scope, tool="db.exec", effect="destructive").outside
    True
"""

from __future__ import annotations

import fnmatch
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from arbitr.core.spec import EFFECT_RANK, Effect

if TYPE_CHECKING:
    from collections.abc import Iterable

    from arbitr.policy.engine import ResolvedResource


class Scope(BaseModel):
    """What a run may do. Unset fields do not restrict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task: str | None = Field(default=None, max_length=4000)
    allowed_tools: tuple[str, ...] | None = None
    allowed_resource_tags: tuple[str, ...] | None = None
    max_effect: Effect | None = None
    spend_limit: float | None = Field(default=None, gt=0)

    def is_within(self, parent: Scope) -> bool:
        """Return whether this scope allows nothing the parent does not."""
        if parent.allowed_tools is not None and (
            self.allowed_tools is None
            or not all(_covered(g, parent.allowed_tools) for g in self.allowed_tools)
        ):
            return False
        if parent.allowed_resource_tags is not None and (
            self.allowed_resource_tags is None
            or not set(self.allowed_resource_tags) <= set(parent.allowed_resource_tags)
        ):
            return False
        if parent.max_effect is not None and (
            self.max_effect is None or EFFECT_RANK[self.max_effect] > EFFECT_RANK[parent.max_effect]
        ):
            return False
        return parent.spend_limit is None or (
            self.spend_limit is not None and self.spend_limit <= parent.spend_limit
        )


_WILDCARDS = frozenset("*?[")


def _covered(child_glob: str, parent_globs: Iterable[str]) -> bool:
    """Whether every name the child pattern matches is matched by a parent pattern.

    Conservative. A plain name is covered when a parent pattern matches it. A
    pattern with wildcards is covered only by an identical parent pattern, or
    by a parent ``prefix*`` whose prefix has no wildcards and starts the child
    pattern. So ``fs.read*`` is inside ``fs.*``, while ``a*c`` is not inside
    ``a?c`` and ``shell.*`` is not inside ``shell.pytest*``.
    """
    if not _WILDCARDS & set(child_glob):
        return any(fnmatch.fnmatchcase(child_glob, p) for p in parent_globs)
    return any(child_glob == p or _is_prefix_glob_of(p, child_glob) for p in parent_globs)


def _is_prefix_glob_of(parent: str, child: str) -> bool:
    prefix = parent[:-1]
    return (
        parent.endswith("*")
        and not _WILDCARDS & set(prefix)
        and child.startswith(prefix)
        and not _WILDCARDS & set(child[: len(prefix)])
    )


@dataclass(frozen=True)
class ScopeVerdict:
    """Whether an action falls outside the run's scope, and why."""

    outside: bool
    reasons: tuple[str, ...] = ()


def check_scope(  # noqa: PLR0913, every check reads one part of the action
    scope: Scope,
    *,
    tool: str,
    effect: Effect,
    resources: Iterable[ResolvedResource] = (),
    amount: float | None = None,
    spent: float = 0.0,
) -> ScopeVerdict:
    """Check one action against a run's scope.

    Reasons name tools, effects and resource ids or kinds, never argument
    values or the task text.
    """
    reasons: list[str] = []
    if scope.allowed_tools is not None and not any(
        fnmatch.fnmatchcase(tool, g) for g in scope.allowed_tools
    ):
        reasons.append(f"tool {tool} is not in the run's allowed tools")
    if scope.max_effect is not None and EFFECT_RANK[effect] > EFFECT_RANK[scope.max_effect]:
        reasons.append(f"effect {effect} is above the run's maximum effect {scope.max_effect}")
    if scope.allowed_resource_tags is not None:
        allowed = set(scope.allowed_resource_tags)
        reasons.extend(
            f"resource {r.id or r.kind} has none of the run's allowed tags"
            for r in resources
            if not r.tags & allowed
        )
    if scope.spend_limit is not None and effect == "financial":
        if amount is None or not math.isfinite(amount) or amount < 0:
            reasons.append("the spend amount cannot be measured against the run's spend limit")
        elif spent + amount > scope.spend_limit:
            reasons.append("the spend would exceed the run's spend limit")
    return ScopeVerdict(outside=bool(reasons), reasons=tuple(reasons))
