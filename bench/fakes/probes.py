"""Probe functions for the fake services, in the ``package.module:function`` form tools use."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arbitr.executor import ProbeCall


def find_refund(call: ProbeCall) -> dict[str, object] | None:
    """Ask FakePayments whether the refund for this intent already happened."""
    service = call.context["payments"]
    return service.find_refund(str(call.args["order_id"]), call.idempotency_key)  # type: ignore[no-any-return,attr-defined]
