"""Arbitr error types.

Every error carries a stable machine-readable ``code`` and a plain-English
message. Errors that reach an agent (``ActionError`` and its subclasses) also
provide ``to_tool_message()``, a short text the model can read and act on.

Example:
    >>> err = CanonicalizationError("NaN or Infinity has no JSON form")
    >>> err.code, str(err)
    ('canonicalization_error', 'NaN or Infinity has no JSON form')
"""

from __future__ import annotations

from typing import ClassVar


class ArbitrError(Exception):
    """Base class for every error Arbitr raises on purpose."""

    code: ClassVar[str] = "arbitr_error"


class CanonicalizationError(ArbitrError, ValueError):
    """A value has no exact canonical JSON form, so it cannot be hashed safely."""

    code: ClassVar[str] = "canonicalization_error"


class JsonPathError(ArbitrError, ValueError):
    """A JSON path is invalid or uses syntax outside the supported subset."""

    code: ClassVar[str] = "invalid_json_path"


class PolicyError(ArbitrError, ValueError):
    """A policy file is malformed or invalid. The old policy keeps running."""

    code: ClassVar[str] = "invalid_policy"


class ScopeError(ArbitrError, ValueError):
    """A run tried to take a scope wider than its parent's."""

    code: ClassVar[str] = "scope_widened"


class ResourceError(ArbitrError, RuntimeError):
    """A tool's resource extractor failed. The action does not run (fail closed)."""

    code: ClassVar[str] = "resource_extractor_failed"


class IntentError(ArbitrError, ValueError):
    """A tool call cannot be turned into an intent (bad arguments or identifiers)."""

    code: ClassVar[str] = "invalid_intent"


class StorageError(ArbitrError, RuntimeError):
    """The ledger could not be read or written. Actions do not run (fail closed)."""

    code: ClassVar[str] = "storage_error"


class StaleStateError(ArbitrError, RuntimeError):
    """Another writer changed the intent first, or it already exists."""

    code: ClassVar[str] = "stale_state"


class IllegalTransitionError(ArbitrError, RuntimeError):
    """An intent was asked to make a state change the state machine does not allow.

    This always means a bug in Arbitr, never a user error.
    """

    code: ClassVar[str] = "illegal_transition"


class RunContextError(ArbitrError, RuntimeError):
    """A tool was called outside ``ledger.run(...)``, so there is no run to record it in."""

    code: ClassVar[str] = "no_run"


class ApprovalError(ArbitrError, ValueError):
    """An approval vote or link was refused: wrong intent, expired, decided, or not allowed."""

    code = "approval_error"


class ActionError(ArbitrError):
    """An action did not run (or its outcome is not known). Agents get ``to_tool_message()``."""

    code: ClassVar[str] = "action_error"

    def to_tool_message(self) -> str:
        """A short plain-English text for the model: what happened and what to do."""
        return str(self)


class ActionDenied(ActionError):
    """The policy refused the action."""

    code: ClassVar[str] = "action_denied"

    def __init__(self, rule_id: str, reason: str) -> None:
        """Record which rule refused the action and why."""
        super().__init__(f"denied by rule {rule_id}: {reason}")
        self.rule_id = rule_id
        self.reason = reason

    def to_tool_message(self) -> str:  # noqa: D102
        return f"Blocked by policy '{self.rule_id}': {self.reason} Do not retry. Ask the user."


class ApprovalPending(ActionError):
    """The action waits for a human decision."""

    code: ClassVar[str] = "approval_pending"

    def __init__(self, approval_id: str, rule_id: str, reason: str) -> None:
        """Record the approval request and the rule that asked for it."""
        super().__init__(f"approval {approval_id} pending (rule {rule_id}): {reason}")
        self.approval_id = approval_id
        self.rule_id = rule_id
        self.reason = reason

    def to_tool_message(self) -> str:  # noqa: D102
        return (
            f"This action needs human approval (request {self.approval_id}): {self.reason}"
            " It has not run. Do not retry now; tell the user it is waiting for approval."
        )


class ApprovalRejected(ActionError):
    """A human rejected the action, the approval expired, or the action was cancelled."""

    code: ClassVar[str] = "approval_rejected"

    def to_tool_message(self) -> str:  # noqa: D102
        return f"This action was not approved ({self}). Do not retry. Ask the user."


class ActionScheduled(ActionError):
    """The action is committed but waits out a cancel window before it runs."""

    code: ClassVar[str] = "action_scheduled"

    def __init__(self, intent_id: str, run_at: str) -> None:
        """Record when the scheduled action is due."""
        super().__init__(f"intent {intent_id} is scheduled to run at {run_at}")
        self.intent_id = intent_id
        self.run_at = run_at

    def to_tool_message(self) -> str:  # noqa: D102
        return (
            f"Scheduled: this action will run at {self.run_at} unless someone cancels it first."
            " Do not call it again."
        )


class InFlight(ActionError):
    """The same action is already running in another worker."""

    code: ClassVar[str] = "in_flight"

    def to_tool_message(self) -> str:  # noqa: D102
        return "This exact action is already running. Do not retry; wait for it to finish."


class UnknownOutcome(ActionError):
    """The action may have happened, and it cannot safely be run again without a human."""

    code: ClassVar[str] = "unknown_outcome"

    def to_tool_message(self) -> str:  # noqa: D102
        return (
            "The action may or may not have happened, and running it again could do it twice."
            " Do not retry. Ask the user to check."
        )


class AmbiguousToolError(ArbitrError, RuntimeError):
    """A tool may have acted in a way that cannot be checked: the ledger records UNKNOWN.

    Integrations raise it when a framework ran a tool without the values the
    ledger meant to inject, so a native tool may have acted without its key.
    """

    code = "ambiguous_tool"


class ScrubbedToolError(Exception):
    """A tool error whose text showed an injected credential, replaced by a safe copy.

    The message keeps the original exception type and its scrubbed text; the
    original exception is not chained, so the credential cannot surface.
    """


class LedgerUnavailable(ActionError):
    """The ledger could not be written, so the action did not run (fail closed)."""

    code: ClassVar[str] = "ledger_unavailable"

    def to_tool_message(self) -> str:  # noqa: D102
        return "The action did not run because the safety ledger is unavailable. Try again later."
