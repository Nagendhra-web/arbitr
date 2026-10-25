"""Policy case tables: unit tests for a policy, run with ``arbitr policy test``.

A case file lists sample tool calls and the decision each one should get::

    cases:
      - name: dropping a prod table is denied
        tool: db.exec
        args: { dsn: "postgres://app@db.prod/orders", sql: "DROP TABLE users" }
        expect: deny
        expect_rule: no-destroy-prod     # optional

Each case runs through the same steps as a real call: resources are extracted
and tagged, the effect is raised by the extractors, outbound arguments are
scanned, and the gate decides. Optional fields set the rest of the context:
``effect`` (the tool's registered effect, default ``write``), ``principal``,
``agent``, ``run_id``, ``run_taint``, ``outside_scope``, ``scopes``, ``now``,
``counters`` (budget counters), ``mode`` and ``outbound_findings``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from arbitr.core.errors import PolicyError
from arbitr.core.spec import ToolSpec
from arbitr.core.taint import Taint
from arbitr.policy.dlp import outbound_findings
from arbitr.policy.engine import GateInput, decide
from arbitr.policy.schema import EffectName, Outcome, format_errors, load_yaml
from arbitr.resources.registry import classify

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from arbitr.policy.engine import Decision
    from arbitr.policy.schema import Policy

DEFAULT_NOW = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)
"""A Monday at noon UTC, so cases without ``now`` are inside working hours."""


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CaseTaint(_Model):
    """Run taint for a case."""

    untrusted_input: bool = False
    private_data: bool = False


class Case(_Model):
    """One sample tool call and the decision it should get."""

    name: str = Field(min_length=1, max_length=200)
    tool: str
    effect: EffectName = "write"
    args: dict[str, Any] = Field(default_factory=dict)
    principal: str = "tester"
    agent: str = "agent"
    run_id: str = "run"
    run_taint: CaseTaint = CaseTaint()
    outside_scope: bool = False
    scopes: tuple[str, ...] = ()
    now: datetime = DEFAULT_NOW
    counters: dict[str, float] = Field(default_factory=dict)
    mode: Literal["enforce", "shadow"] | None = None
    outbound_findings: tuple[str, ...] | None = None
    expect: Outcome
    expect_rule: str | None = None

    @field_validator("tool")
    @classmethod
    def _tool_name(cls, value: str) -> str:
        ToolSpec(name=value, effect="read")  # same naming rules as real tools
        return value

    @field_validator("now")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("now needs a timezone, for example 2026-12-24T10:00:00Z")
        return value


class CaseFile(_Model):
    """A whole case file."""

    cases: tuple[Case, ...] = Field(min_length=1)

    @field_validator("cases")
    @classmethod
    def _unique(cls, value: tuple[Case, ...]) -> tuple[Case, ...]:
        seen: set[str] = set()
        for case in value:
            if case.name in seen:
                raise ValueError(f"duplicate case name {case.name!r}")
            seen.add(case.name)
        return value


def load_cases(source: str | Path) -> tuple[Case, ...]:
    """Load a case file from YAML text or a path.

    Raises:
        PolicyError: the file is not valid YAML or not a valid case table.
    """
    data = load_yaml(source, "case file")
    try:
        return CaseFile.model_validate(data).cases
    except ValidationError as exc:
        raise PolicyError(format_errors(exc, "case file")) from exc


def gate_input(case: Case, policy: Policy) -> GateInput:
    """Build what the gate sees for a case, the same way a real call is prepared."""
    spec = ToolSpec(name=case.tool, effect=case.effect)
    classified = classify(spec, case.args, policy)
    findings = case.outbound_findings
    if findings is None:
        findings = tuple(outbound_findings(classified.effect, case.args))
    return GateInput(
        tool=case.tool,
        effect=classified.effect,
        args=case.args,
        principal=case.principal,
        agent_id=case.agent,
        run_id=case.run_id,
        now=case.now,
        resources=classified.resources,
        taint=Taint(case.run_taint.untrusted_input, case.run_taint.private_data),
        scopes=frozenset(case.scopes),
        outside_scope=case.outside_scope,
        outbound_findings=frozenset(findings),
        mode=case.mode,
    )


@dataclass(frozen=True)
class CaseResult:
    """How one case went."""

    case: Case
    decision: Decision

    @property
    def ok(self) -> bool:
        """Whether the outcome (and the rule, when given) matched."""
        rule_ok = self.case.expect_rule is None or self.case.expect_rule == self.decision.rule_id
        return self.decision.outcome == self.case.expect and rule_ok

    def describe(self) -> str:
        """``PASS name`` or a ``FAIL`` line followed by the full explanation."""
        if self.ok:
            return f"PASS {self.case.name}"
        expected: str = self.case.expect
        if self.case.expect_rule is not None:
            expected = f"{expected} by rule {self.case.expect_rule}"
        head = (
            f"FAIL {self.case.name}: expected {expected}, got {self.decision.outcome}"
            f" by rule {self.decision.rule_id}"
        )
        body = "\n".join("    " + line for line in self.decision.explain().splitlines())
        return f"{head}\n{body}"

    def to_dict(self) -> dict[str, object]:
        """The machine-readable form."""
        return {
            "name": self.case.name,
            "ok": self.ok,
            "expect": self.case.expect,
            "expect_rule": self.case.expect_rule,
            "outcome": self.decision.outcome,
            "rule_id": self.decision.rule_id,
            "reason": self.decision.reason,
        }


@dataclass(frozen=True)
class CaseReport:
    """Every case result, in file order."""

    results: tuple[CaseResult, ...]

    @property
    def passed(self) -> int:
        """How many cases passed."""
        return sum(1 for r in self.results if r.ok)

    @property
    def failed(self) -> int:
        """How many cases failed."""
        return len(self.results) - self.passed

    @property
    def ok(self) -> bool:
        """Whether every case passed."""
        return self.failed == 0

    def describe(self, *, explain: bool = False) -> str:
        """One line per case (with explanations for failures) and a summary."""
        lines = []
        for result in self.results:
            lines.append(result.describe())
            if explain and result.ok:
                lines.extend("    " + x for x in result.decision.explain().splitlines())
        lines.append(f"{self.passed} passed, {self.failed} failed")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        """The machine-readable form."""
        return {
            "passed": self.passed,
            "failed": self.failed,
            "results": [r.to_dict() for r in self.results],
        }


def run_cases(policy: Policy, cases: Iterable[Case]) -> CaseReport:
    """Decide every case with the policy."""
    results = []
    for case in cases:
        decision = decide(gate_input(case, policy), policy, case.counters)
        results.append(CaseResult(case, decision))
    return CaseReport(tuple(results))
