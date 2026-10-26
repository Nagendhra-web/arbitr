"""The policy file format: models, loading and the published JSON Schema.

A policy is data, never code. It is loaded with a safe YAML loader that also
refuses duplicate keys, validated by strict models (unknown fields are
errors), and frozen. ``json_schema()`` produces the schema published as
``policy.schema.json`` so editors can validate and autocomplete policy files.

Example:
    >>> policy = load_policy("{version: 1, mode: shadow}")
    >>> policy.mode, policy.default.destructive
    ('shadow', 'require_approval')
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Final, Literal

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from arbitr.core.errors import JsonPathError, PolicyError
from arbitr.policy import jsonpath
from arbitr.policy.regex import compile_rule_regex

Outcome = Literal["allow", "deny", "require_approval"]
Verdict = Literal["allow", "deny", "require_approval", "delay"]
"""What a rule's ``then`` can say: an outcome, or a delay (a cancel window)."""
MAX_DELAY_SECONDS: Final = 86_400
_DELAY_UNITS: Final = {"s": 1, "m": 60, "h": 3600}


def _parse_delay(text: str) -> int:
    """``delay 60s``, ``delay 5m``, ``delay 2h`` or ``delay 90`` (seconds) to seconds."""
    parts = text.split()
    if len(parts) != 2 or parts[0] != "delay":  # noqa: PLR2004, the word and the duration
        raise ValueError("write a delay as 'delay 60s', 'delay 5m' or 'delay 2h'")
    value = parts[1]
    unit = value[-1] if value[-1] in _DELAY_UNITS else "s"
    number = value[:-1] if value[-1] in _DELAY_UNITS else value
    if not (number.isascii() and number.isdigit()):
        raise ValueError("a delay is a whole number of seconds, minutes or hours")
    return int(number) * _DELAY_UNITS[unit]


EffectName = Literal["read", "write", "destructive", "external_comm", "financial"]
ArgOp = Literal[
    "eq",
    "ne",
    "in",
    "not_in",
    "gt",
    "gte",
    "lt",
    "lte",
    "glob",
    "regex",
    "contains",
    "exists",
    "len_gt",
]
BudgetScope = Literal["principal", "agent", "run", "tool", "day", "hour"]

_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_DURATION = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")
_UNITS: Final = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: object) -> timedelta:
    """Parse ``30s``, ``15m``, ``2h``, ``1d`` or a number of seconds.

    Example:
        >>> parse_duration("15m")
        datetime.timedelta(seconds=900)
    """
    if isinstance(value, timedelta):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return timedelta(seconds=value)
    match = _DURATION.match(str(value)) if isinstance(value, str) else None
    if not match:
        raise ValueError(f"invalid duration {value!r}: use a number with s, m, h or d")
    return timedelta(seconds=int(match.group(1)) * _UNITS[match.group(2)])


Duration = Annotated[timedelta, BeforeValidator(parse_duration)]


def check_safe_regex(pattern: str) -> str:
    """Accept only patterns the linear-time regex engine runs.

    Example:
        >>> check_safe_regex(r"^prod-[a-z]+$")
        '^prod-[a-z]+$'
    """
    compile_rule_regex(pattern)
    return pattern


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ArgCondition(_Model):
    """A test on the tool arguments: ``{path, op, value}``."""

    path: str
    op: ArgOp
    value: Any = None

    @field_validator("path")
    @classmethod
    def _check_path(cls, value: str) -> str:
        try:
            jsonpath.parse(value)
        except JsonPathError as exc:
            raise ValueError(f"path: {exc}") from exc
        return value

    @model_validator(mode="after")
    def _check_value(self) -> ArgCondition:
        v = self.value
        if self.op in {"in", "not_in"} and not isinstance(v, list | tuple):
            raise ValueError(f"op {self.op} needs a list value")
        if self.op in {"gt", "gte", "lt", "lte", "len_gt"} and (
            isinstance(v, bool) or not isinstance(v, int | float)
        ):
            raise ValueError(f"op {self.op} needs a number value")
        if self.op in {"glob", "regex"} and not isinstance(v, str):
            raise ValueError(f"op {self.op} needs a string value")
        if self.op == "regex":
            check_safe_regex(v)
        if self.op == "exists" and v is not None and not isinstance(v, bool):
            raise ValueError("op exists takes true, false or no value")
        return self


class TimeWindowCondition(_Model):
    """Matches while the named window is active."""

    cron_active: str


class TaintCondition(_Model):
    """Matches on run taint flags. Unset flags are not checked."""

    untrusted_input: bool | None = None
    private_data: bool | None = None


class ResourceCount(_Model):
    """More than ``value`` distinct resources of one kind (for example email recipients)."""

    kind: str = Field(min_length=1)
    value: int = Field(ge=0)


class When(_Model):
    """Conditions of a rule. All given conditions must hold."""

    tool: str | None = None
    tool_glob: str | None = None
    effect: EffectName | None = None
    effect_in: tuple[EffectName, ...] | None = None
    principal_in: tuple[str, ...] | None = None
    agent_in: tuple[str, ...] | None = None
    resource_tags_any: tuple[str, ...] | None = None
    resource_tags_all: tuple[str, ...] | None = None
    resource_ids_any: tuple[str, ...] | None = None
    resource_count_gt: ResourceCount | None = None
    run_taint: TaintCondition | None = None
    time_window: TimeWindowCondition | None = None
    args: tuple[ArgCondition, ...] | None = None
    outside_scope: bool | None = None
    scope_required: str | None = None
    outbound_findings_any: tuple[str, ...] | None = None
    preview: tuple[ArgCondition, ...] | None = None
    """Tests on the action's preview facts, with the same operators as ``args``."""

    @model_validator(mode="after")
    def _not_empty(self) -> When:
        if all(getattr(self, name) is None for name in type(self).model_fields):
            raise ValueError("a rule needs at least one condition in 'when'")
        return self


class Budget(_Model):
    """A running limit: a sum of an argument, or a count of calls, per scope."""

    scope: tuple[BudgetScope, ...] = Field(min_length=1)
    sum_path: str | None = None
    count: bool = False
    limit: float = Field(gt=0)

    @model_validator(mode="after")
    def _one_measure(self) -> Budget:
        if (self.sum_path is None) == (not self.count):
            raise ValueError("a budget needs exactly one of sum_path or count: true")
        if self.sum_path is not None:
            try:
                jsonpath.parse(self.sum_path)
            except JsonPathError as exc:
                raise ValueError(f"sum_path: {exc}") from exc
        if len(set(self.scope)) != len(self.scope):
            raise ValueError("budget scope lists a dimension twice")
        return self


class ApprovalRequirement(_Model):
    """Who must approve: how many distinct people, from which roles."""

    required: int = Field(default=1, ge=1, le=10)
    roles: tuple[str, ...] | None = None
    """An approver must hold one of these roles; None means anyone may approve."""
    separate_from_principal: bool = False
    """The principal the agent acts for may not approve the action."""


class Rule(_Model):
    """One policy rule: conditions, then an outcome (or a budget and its outcome)."""

    id: str
    when: When
    then: Verdict | None = None
    delay_seconds: float | None = Field(default=None, gt=0, le=MAX_DELAY_SECONDS)
    budget: Budget | None = None
    then_exceeded: Outcome | None = None
    reason: str = Field(min_length=1, max_length=500)
    always_enforce: bool = False
    approvals: ApprovalRequirement | None = None
    """Who must approve, when this rule asks for approval (the policy default otherwise)."""

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        if not _ID.match(value):
            raise ValueError(
                "rule id must be lowercase letters, digits and . _ - (at most 64 characters)"
            )
        return value

    @model_validator(mode="before")
    @classmethod
    def _split_delay(cls, data: object) -> object:
        """Turn ``then: delay 60s`` into ``then: delay`` plus ``delay_seconds: 60``."""
        if not isinstance(data, dict):
            return data
        then = data.get("then")
        if isinstance(then, str) and then.strip().startswith("delay") and then.strip() != "delay":
            if "delay_seconds" in data:
                raise ValueError("give the delay once: in 'then' or in delay_seconds")
            return {**data, "then": "delay", "delay_seconds": _parse_delay(then)}
        return data

    @model_validator(mode="after")
    def _one_outcome(self) -> Rule:
        if self.budget is not None:
            if self.then is not None:
                raise ValueError("a rule has either 'then' or a budget with 'then_exceeded'")
            if self.then_exceeded is None:
                raise ValueError("a budget rule needs then_exceeded")
        else:
            if self.then is None:
                raise ValueError("a rule needs 'then' (allow, deny or require_approval)")
            if self.then_exceeded is not None:
                raise ValueError("then_exceeded only applies to budget rules")
        if (self.then == "delay") != (self.delay_seconds is not None):
            raise ValueError("a delay needs a duration, for example 'then: delay 60s'")
        if self.approvals is not None and "require_approval" not in (self.then, self.then_exceeded):
            raise ValueError("approvals only apply to a rule that asks for approval")
        return self


class ResourceMatch(_Model):
    """How a resource definition recognizes an extracted resource."""

    kind: str
    uri_glob: str | None = None
    glob: str | None = None
    attrs: dict[str, str] | None = None


class ResourceDef(_Model):
    """A named resource with tags rules can match on."""

    id: str
    match: ResourceMatch
    tags: tuple[str, ...] = ()


class Window(_Model):
    """A named time window, ``start`` inclusive and ``end`` exclusive."""

    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _check(self) -> Window:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("window times need a timezone, for example 2026-12-20T00:00:00Z")
        if self.end <= self.start:
            raise ValueError("window end must be after its start")
        return self


class Defaults(_Model):
    """The outcome per effect when no rule matches. Safe by default."""

    read: Outcome = "allow"
    write: Outcome = "allow"
    destructive: Outcome = "require_approval"
    external_comm: Outcome = "allow"
    financial: Outcome = "require_approval"


class ApprovalSettings(ApprovalRequirement):
    """How approvals behave, and who must approve when a rule does not say."""

    wait_seconds: int = Field(default=0, ge=0, le=3600)
    expires_after: Duration = timedelta(minutes=15)

    @field_validator("expires_after", mode="before")
    @classmethod
    def _duration_message(cls, value: object) -> object:
        try:
            return parse_duration(value)
        except ValueError as exc:
            raise ValueError(f"duration: {exc}") from exc


class Policy(_Model):
    """A whole policy file."""

    model_config = ConfigDict(frozen=True, extra="forbid", title="Arbitr policy")

    version: Literal[1]
    mode: Literal["enforce", "shadow"] = "enforce"
    default: Defaults = Defaults()
    on_unknown: Literal["require_approval", "fail", "retry"] = "require_approval"
    on_outside_scope: Outcome = "require_approval"
    approval: ApprovalSettings = ApprovalSettings()
    include: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()
    resources: tuple[ResourceDef, ...] = ()
    rules: tuple[Rule, ...] = ()
    windows: dict[str, Window] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _cross_checks(self) -> Policy:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)
            window = rule.when.time_window
            if window is not None and window.cron_active not in self.windows:
                raise ValueError(
                    f"rule {rule.id!r} refers to window {window.cron_active!r},"
                    " which is not defined under 'windows'"
                )
        ids = [r.id for r in self.resources]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate resource id {sorted(dupes)[0]!r}")
        return self


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate keys instead of keeping the last one."""


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    keys: set[object] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in keys:
            raise PolicyError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        keys.add(key)
    return dict(loader.construct_pairs(node, deep=True))


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def format_errors(exc: ValidationError, what: str = "policy") -> str:
    """One line naming every invalid field and why."""
    lines = []
    for err in exc.errors():
        where = ".".join(str(p) for p in err["loc"]) or what
        message = str(err["msg"]).removeprefix("Value error, ")
        lines.append(f"{where}: {message}")
    return f"invalid {what}: " + "; ".join(lines)


def load_yaml(source: str | Path, what: str) -> Any:  # noqa: ANN401 - any YAML value
    """Parse YAML safely: no custom tags, and duplicate keys are an error.

    Raises:
        PolicyError: the text is not valid YAML or repeats a key.
    """
    text = source.read_text(encoding="utf-8") if isinstance(source, Path) else source
    try:
        # _UniqueKeyLoader subclasses SafeLoader, so no Python objects are built.
        return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506  # nosec B506
    except PolicyError:
        raise
    except yaml.YAMLError as exc:
        raise PolicyError(f"{what} is not valid YAML: {exc}") from exc


def load_policy(source: str | Path) -> Policy:
    """Load and validate a policy from YAML text or a file path.

    Raises:
        PolicyError: the YAML is malformed, has duplicate keys or unsafe tags,
            or does not describe a valid policy. The message says what and where.
    """
    data = load_yaml(source, "policy")
    if not isinstance(data, dict):
        raise PolicyError("a policy must be a mapping with at least 'version: 1'")
    try:
        return Policy.model_validate(_with_packs(data))
    except ValidationError as exc:
        raise PolicyError(format_errors(exc)) from exc


_PACK_KEYS: Final = frozenset({"version", "resources", "rules", "windows"})


def _merge_by_id(base: list[Any], overrides: list[Any]) -> list[Any]:
    """Entries of ``overrides`` replace entries of ``base`` with the same id, in place."""
    position = {item.get("id"): i for i, item in enumerate(base) if isinstance(item, dict)}
    merged = list(base)
    for item in overrides:
        key = item.get("id") if isinstance(item, dict) else None
        if key in position:
            merged[position[key]] = item
        else:
            merged.append(item)
    return merged


def _with_packs(data: dict[str, Any]) -> dict[str, Any]:
    """Expand ``include`` and apply ``exclude_rules``.

    Pack resources and rules come first, in include order. A resource or rule
    in the policy with the same id as a pack entry replaces it. Because the
    strictest outcome wins, loosening a pack rule means excluding it.
    """
    from arbitr.policy.packs import PACKS, pack_text  # noqa: PLC0415 - packs import this module

    include = data.get("include") or []
    exclude = data.get("exclude_rules") or []
    for key, value in (("include", include), ("exclude_rules", exclude)):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise PolicyError(f"{key} must be a list of names")
    for key in ("resources", "rules"):
        items = data.get(key)
        if items is not None and (
            not isinstance(items, list) or not all(isinstance(i, dict) for i in items)
        ):
            raise PolicyError(f"{key} must be a list of mappings")
    if data.get("windows") is not None and not isinstance(data.get("windows"), dict):
        raise PolicyError("windows must be a mapping of names to windows")
    resources: list[Any] = []
    rules: list[Any] = []
    windows: dict[str, Any] = {}
    for name in include:
        if name not in PACKS:
            raise PolicyError(f"unknown pack {name!r}; packs: {', '.join(PACKS)}")
        pack = load_yaml(pack_text(name), f"pack {name}")
        extra = sorted(set(pack) - _PACK_KEYS)
        if extra:
            raise PolicyError(f"pack {name} has keys a pack cannot set: {', '.join(extra)}")
        resources.extend(pack.get("resources") or [])
        rules.extend(pack.get("rules") or [])
        windows.update(pack.get("windows") or {})
    merged = dict(data)
    merged["resources"] = _merge_by_id(resources, list(data.get("resources") or []))
    merged["rules"] = _merge_by_id(rules, list(data.get("rules") or []))
    merged["windows"] = {**windows, **(data.get("windows") or {})}
    known = {r.get("id") for r in merged["rules"] if isinstance(r, dict)}
    missing = sorted(set(exclude) - known)
    if missing:
        raise PolicyError(f"exclude_rules names rules that do not exist: {', '.join(missing)}")
    merged["rules"] = [r for r in merged["rules"] if r.get("id") not in exclude]
    return merged


def json_schema() -> dict[str, Any]:
    """The JSON Schema for policy files, as published in ``policy.schema.json``."""
    return Policy.model_json_schema()
