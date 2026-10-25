"""Arbitr error types.

Every error carries a stable machine-readable ``code`` and a plain-English
message. Errors that reach an agent also provide ``to_tool_message()`` (added
with the executor), a short text the model can read and act on.

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
