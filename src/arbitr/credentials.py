"""Credential injection: the agent never sees the secrets its tools use.

A tool declares the credentials it needs (``ToolSpec(credentials=("stripe_live",))``).
The executor fetches them only after the gate allows the action, passes them
to the tool function as ``credentials={name: value}``, and never stores, logs
or returns them. A denied action never fetches a credential.

Providers:

- ``EnvCredentials``: ``ARBITR_CRED_<NAME>`` environment variables.
- ``FileCredentials``: one file per credential in a folder that only the
  owner can read. On POSIX systems a file readable by other users is refused.
- ``ChainCredentials``: tries several providers in order.

Example:
    >>> provider = EnvCredentials(environ={"ARBITR_CRED_STRIPE_LIVE": "sk_x"})
    >>> provider.get("stripe_live")
    'sk_x'
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

from arbitr.core.errors import ArbitrError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


class CredentialError(ArbitrError, LookupError):
    """A credential is missing or stored unsafely. The action does not run."""

    code = "credential_error"


class CredentialProvider(Protocol):
    """Returns the secret value for a credential name."""

    def get(self, name: str) -> str:
        """The value, or raise CredentialError."""
        ...


def _check_name(name: str) -> str:
    if not _NAME.match(name):
        raise CredentialError(f"invalid credential name {name!r}")
    return name


class EnvCredentials:
    """Credentials from ``ARBITR_CRED_<NAME>`` environment variables."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        """Read from ``environ`` (the process environment by default)."""
        self._environ = environ if environ is not None else os.environ

    def get(self, name: str) -> str:
        """The value of ``ARBITR_CRED_<NAME>`` (dots and dashes become underscores)."""
        key = "ARBITR_CRED_" + re.sub(r"[.-]", "_", _check_name(name)).upper()
        value = self._environ.get(key)
        if not value:
            raise CredentialError(f"credential {name} is not set ({key})")
        return value


class FileCredentials:
    """Credentials from files named after them in one folder, readable by the owner only."""

    def __init__(self, folder: str | Path) -> None:
        """Read credentials from ``folder``."""
        self._folder = Path(folder)

    def get(self, name: str) -> str:
        """The file's content, without the trailing newline.

        Raises:
            CredentialError: missing, empty, or readable by group or others (POSIX).
        """
        path = self._folder / _check_name(name)
        try:
            info = path.stat()
            if sys.platform != "win32" and info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise CredentialError(f"credential file {path} is readable by other users")
            value = path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise CredentialError(f"credential {name} cannot be read") from exc
        if not value:
            raise CredentialError(f"credential {name} is empty")
        return value


class ChainCredentials:
    """Try providers in order; the first one that has the credential wins."""

    def __init__(self, providers: Sequence[CredentialProvider]) -> None:
        """Use ``providers`` in the given order."""
        self._providers = tuple(providers)

    def get(self, name: str) -> str:
        """The first provider's value for ``name``."""
        for provider in self._providers:
            try:
                return provider.get(name)
            except CredentialError:
                continue
        raise CredentialError(f"credential {name} is not available from any provider")
