"""An in-memory keyring backend, so tests never touch the real OS keyring."""

from __future__ import annotations

from keyring.backend import KeyringBackend
from keyring.errors import KeyringError


class FakeKeyring(KeyringBackend):
    """Holds entries in a dict; ``fail = True`` makes reads raise like a locked backend."""

    priority = 1  # type: ignore[assignment]

    def __init__(self, entries: dict[tuple[str, str], str] | None = None) -> None:
        super().__init__()
        self.entries = dict(entries or {})
        self.fail = False

    def get_password(self, service: str, username: str) -> str | None:
        if self.fail:
            raise KeyringError("backend locked")
        return self.entries.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.entries[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.entries[(service, username)]
