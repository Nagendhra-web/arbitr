"""Arbitr: a write-ahead ledger and deterministic gate for AI agent actions.

The main names are importable from the package itself. They load on first
use, so ``import arbitr`` stays cheap.

Example:
    >>> import arbitr
    >>> isinstance(arbitr.__version__, str)
    True
    >>> arbitr.ToolSpec(name="db.query", effect="read").effect
    'read'
"""

from __future__ import annotations

import importlib
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arbitr.core.errors import (
        ActionDenied,
        ActionError,
        ActionScheduled,
        ApprovalPending,
        ApprovalRejected,
        ArbitrError,
        InFlight,
        LedgerUnavailable,
        RunContextError,
        UnknownOutcome,
    )
    from arbitr.core.spec import ToolSpec
    from arbitr.executor import Ledger
    from arbitr.guarding import guard

try:
    __version__: str = version("arbitr")
except PackageNotFoundError:  # pragma: no cover, only when running from a bare source tree
    __version__ = "0.0.0+unknown"

_LAZY = {
    "Ledger": "arbitr.executor",
    "ToolSpec": "arbitr.core.spec",
    "guard": "arbitr.guarding",
    "ActionError": "arbitr.core.errors",
    "ActionDenied": "arbitr.core.errors",
    "ApprovalPending": "arbitr.core.errors",
    "ApprovalRejected": "arbitr.core.errors",
    "ActionScheduled": "arbitr.core.errors",
    "InFlight": "arbitr.core.errors",
    "UnknownOutcome": "arbitr.core.errors",
    "LedgerUnavailable": "arbitr.core.errors",
    "ArbitrError": "arbitr.core.errors",
    "RunContextError": "arbitr.core.errors",
}

__all__ = [
    "ActionDenied",
    "ActionError",
    "ActionScheduled",
    "ApprovalPending",
    "ApprovalRejected",
    "ArbitrError",
    "InFlight",
    "Ledger",
    "LedgerUnavailable",
    "RunContextError",
    "ToolSpec",
    "UnknownOutcome",
    "__version__",
    "guard",
]


def __getattr__(name: str) -> object:
    """Load a public name the first time it is used."""
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module 'arbitr' has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value
