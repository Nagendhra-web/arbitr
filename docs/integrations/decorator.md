# Decorator

`guard` routes every call of a function through the ledger. It works for
plain functions and for `async def` functions.

```python
from arbitr import ActionError, Ledger, ToolSpec, guard

ledger = Ledger.from_config()  # arbitr.yaml, or the file in ARBITR_CONFIG

refund_spec = ToolSpec(name="payments.refund", effect="financial", idempotency="native")


@guard(ledger, refund_spec)
def refund(order_id: str, amount: float, *, idempotency_key: str | None = None) -> dict:
    return payments.refund(order_id, amount, idempotency_key=idempotency_key)


with ledger.run(principal="alice@example.com", agent_id="support-bot"):
    try:
        refund("o-1", 25)
    except ActionError as stop:
        print(stop.to_tool_message())
```

## How arguments become an intent

The bound arguments, with defaults filled in, are the intent's arguments. So
`refund("o-1", 25)` and `refund(order_id="o-1", amount=25)` are the same
action, and calling it twice in a run returns the first receipt.

- `idempotency_key` is injected for `native` and `probe` tools. The function
  must accept it; `guard` checks this when it decorates. Pass it yourself to
  choose the key (for example an order's refund id).
- `credentials` is injected for tools that declare credentials, only after
  the gate allows the call. Callers may not pass it.
- Positional-only parameters and `*args` are refused when decorating, since
  every argument needs a name in the ledger. `**kwargs` is fine.

## Late binding

`guard` accepts a zero-argument function in place of the ledger, so tools can
be declared at import time and the ledger opened later:

```python
_ledger: Ledger | None = None


@guard(lambda: _ledger, refund_spec)
def refund(order_id: str, amount: float, *, idempotency_key: str | None = None) -> dict: ...
```

## Errors

A stop raises one of the `ActionError` types (`ActionDenied`,
`ApprovalPending`, `ApprovalRejected`, `ActionScheduled`, `InFlight`,
`UnknownOutcome`, `LedgerUnavailable`). Each has `to_tool_message()`, a short
text you can hand back to the model as the tool result. Errors the function
itself raises are recorded and raised as they are.

See `examples/guard_decorator.py`.
