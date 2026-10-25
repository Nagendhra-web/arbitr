"""Arbitr: a write-ahead ledger and deterministic gate for AI agent actions.

The public API is still being built.

Example:
    >>> import arbitr
    >>> isinstance(arbitr.__version__, str)
    True
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("arbitr")
except PackageNotFoundError:  # pragma: no cover, only when running from a bare source tree
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
