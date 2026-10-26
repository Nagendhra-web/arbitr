"""Fake tools for tests: they record every call and never touch the network.

``FakeTool`` stands in for any tool: it records calls and returns or raises
what you tell it. ``FakePayments`` is a payments service with optional native
idempotency, stored in SQLite so a crashed worker's refunds are still there
to count. The Arbitr bench uses the same fakes.

Example:
    >>> from arbitr.core.spec import ToolSpec
    >>> send = FakeTool(ToolSpec(name="email.send", effect="external_comm"), returns={"id": "m1"})
    >>> send(to="a@example.com")
    {'id': 'm1'}
    >>> send.calls
    [{'to': 'a@example.com'}]
"""

from __future__ import annotations

import sqlite3
import threading
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from arbitr.core.spec import ToolSpec
    from arbitr.executor import ProbeCall

__all__ = ["FakePayments", "FakeTool", "LostResponse", "find_refund"]

_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS refunds (refund_id TEXT PRIMARY KEY, order_id TEXT NOT NULL,"
    " amount REAL NOT NULL, idempotency_key TEXT)"
)


class LostResponse(ConnectionError):  # noqa: N818 - named after what happens
    """The side effect happened, but the reply was lost on the way back."""


class FakeTool:
    """A tool that records its calls. Call it with keyword arguments, as the ledger does.

    ``returns`` is the result (or a function of the call's arguments).
    ``raises`` is raised instead, before any effect. With
    ``lose_response=True`` the call is recorded and then fails with
    ``LostResponse``, as if the reply never arrived.
    """

    def __init__(
        self,
        spec: ToolSpec,
        returns: object = None,
        *,
        raises: BaseException | None = None,
        lose_response: bool = False,
    ) -> None:
        """A fake for the tool ``spec`` describes."""
        self.spec = spec
        self.returns = returns
        self.raises = raises
        self.lose_response = lose_response
        self.calls: list[dict[str, object]] = []
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        """The tool's name, from its spec."""
        return self.spec.name

    def __call__(self, **kwargs: object) -> object:
        """Record the call, then return, raise, or lose the response."""
        if self.raises is not None:
            raise self.raises
        with self._lock:
            self.calls.append(dict(kwargs))
        if self.lose_response:
            raise LostResponse(f"{self.name} acted, but the response was lost")
        if callable(self.returns):
            make: Callable[..., object] = self.returns
            return make(**kwargs)
        return self.returns

    @property
    def count(self) -> int:
        """How many calls had an effect."""
        return len(self.calls)


class FakePayments:
    """Refunds stored in SQLite (a file, or in memory), with optional native idempotency.

    - ``native=True``: an ``idempotency_key`` makes repeated calls return the
      first refund instead of creating another one, like Stripe's
      Idempotency-Key.
    - ``native=False``: every call creates a refund.
    - ``crash_after_effect=True``: the refund is stored, then the call fails
      with ``LostResponse`` as if the reply never arrived.

    ``find_refund(order_id, key)`` is the probe endpoint.
    """

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        native: bool = True,
        crash_after_effect: bool = False,
    ) -> None:
        """Open (or create) the store at ``path``."""
        self.native = native
        self.crash_after_effect = crash_after_effect
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False, timeout=30
        )
        self._conn.execute(_SCHEMA)

    def refund(
        self, order_id: str, amount: float, *, idempotency_key: str | None = None
    ) -> dict[str, object]:
        """Refund an order. With native idempotency, a repeated key returns the first refund."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if self.native and idempotency_key is not None:
                    found = self._by_key(idempotency_key)
                    if found is not None:
                        self._conn.execute("COMMIT")
                        return found
                count = self._conn.execute("SELECT COUNT(*) FROM refunds").fetchone()[0]
                refund_id = f"re_{count + 1:06d}"
                self._conn.execute(
                    "INSERT INTO refunds VALUES (?, ?, ?, ?)",
                    (refund_id, order_id, float(amount), idempotency_key),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        if self.crash_after_effect:
            raise LostResponse("the refund was made but the response was lost")
        return {"refund_id": refund_id, "order_id": order_id, "amount": float(amount)}

    def find_refund(self, order_id: str, idempotency_key: str) -> dict[str, object] | None:
        """The probe: the refund made for this order with this key, if any."""
        with self._lock:
            found = self._by_key(idempotency_key)
        return found if found is not None and found["order_id"] == order_id else None

    def count(self, order_id: str | None = None) -> int:
        """How many refunds exist (for one order, or in total)."""
        with self._lock:
            if order_id is None:
                return int(self._conn.execute("SELECT COUNT(*) FROM refunds").fetchone()[0])
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM refunds WHERE order_id = ?", (order_id,)
                ).fetchone()[0]
            )

    def close(self) -> None:
        """Close the store."""
        self._conn.close()

    def _by_key(self, key: str) -> dict[str, object] | None:
        row = self._conn.execute(
            "SELECT refund_id, order_id, amount FROM refunds WHERE idempotency_key = ?"
            " ORDER BY refund_id LIMIT 1",
            (key,),
        ).fetchone()
        if row is None:
            return None
        return {"refund_id": row[0], "order_id": row[1], "amount": row[2]}


def find_refund(call: ProbeCall) -> dict[str, object] | None:
    """The probe for ``FakePayments`` refunds: ``probe="arbitr.testing.fakes:find_refund"``.

    The service comes from ``ledger.probe_context["payments"]``.
    """
    service = call.context.get("payments")
    find = getattr(service, "find_refund", None)
    if not callable(find):
        raise TypeError('put the FakePayments in ledger.probe_context["payments"]')
    found = find(str(call.args["order_id"]), call.idempotency_key)
    return found if isinstance(found, dict) else None
