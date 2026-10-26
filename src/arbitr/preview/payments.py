"""Payment previews: the total of every ``amount`` in a call, and how many there are.

Every value under a key named ``amount`` counts, at any depth, so a batch
(``{"payouts": [{"amount": 10}, {"amount": 20}]}``) totals 30 in 2 payments.
An amount that is not a finite, non-negative number, mixed currencies, or
arguments too deep or too large to read make the preview fail: a total that
might be wrong is worse than none.

Example:
    >>> preview_payments({"amount": 120, "currency": "eur"}, {}).summary
    '1 payment totalling 120.00 EUR'
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Final

from arbitr.preview.base import Preview, plural

_MAX_NODES: Final = 10_000
_MAX_DEPTH: Final = 64


class Unreadable(Exception):  # noqa: N818 - a reason, not an error the caller handles
    """The amounts cannot be totalled safely."""


def _amount(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise Unreadable("an amount is not a number")
    if not math.isfinite(value) or value < 0:
        raise Unreadable("an amount is negative or not finite")
    return float(value)


def _collect(args: Mapping[str, object]) -> tuple[list[float], set[str]]:
    amounts: list[float] = []
    currencies: set[str] = set()
    stack: list[tuple[object, int]] = [(args, 0)]
    seen = 0
    while stack:
        value, depth = stack.pop()
        seen += 1
        if seen > _MAX_NODES or depth > _MAX_DEPTH:
            raise Unreadable("the arguments are too deep or too large to read")
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key == "amount":
                    amounts.append(_amount(item))
                elif key == "currency" and isinstance(item, str):
                    currencies.add(item.upper())
                else:
                    stack.append((item, depth + 1))
        elif isinstance(value, list | tuple):
            stack.extend((item, depth + 1) for item in value)
    return amounts, currencies


def preview_payments(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
    """Total the amounts in a payment call."""
    try:
        amounts, currencies = _collect(args)
    except Unreadable as exc:
        return Preview.failed(f"No preview: {exc}")
    if not amounts:
        return Preview.failed("No preview: no amount was found in the arguments")
    if len(currencies) > 1:
        return Preview.failed("No preview: the amounts are in more than one currency")
    total = math.fsum(amounts)
    facts: dict[str, int | float | str] = {"amount_total": total, "payments": len(amounts)}
    summary = f"{plural(len(amounts), 'payment')} totalling {total:,.2f}"
    if currencies:
        currency = currencies.pop()
        facts["currency"] = currency
        summary += f" {currency}"
    return Preview(summary, facts)
