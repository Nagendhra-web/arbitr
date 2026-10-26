# OpenAI Agents

`arbitr.integrations.openai_agents` works with the OpenAI Agents SDK
(`openai-agents` 0.24). Install it with `pip install "arbitr[openai-agents]"`.

Use `guarded_function_tool` where you would use the SDK's `function_tool`.
It takes the same options (`name_override`, `needs_approval`, `timeout` and
the rest) and returns a normal `FunctionTool`, whose `on_invoke_tool` asks the
ledger before the function runs.

```python
from agents import Agent, Runner

from arbitr import Ledger, ToolSpec
from arbitr.integrations.openai_agents import guarded_function_tool

ledger = Ledger.from_config()
refund_spec = ToolSpec(name="payments.refund", effect="financial", idempotency="native")


@guarded_function_tool(ledger, refund_spec)
def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
    """Refund an order.

    Args:
        order_id: The order to refund.
        amount: How much to refund.
    """
    made = payments.refund(order_id, amount, idempotency_key=idempotency_key)
    return f"refunded {made['refund_id']}"


agent = Agent(name="support-bot", tools=[refund])

with ledger.run(principal="alice@example.com", agent_id="support-bot"):
    result = await Runner.run(agent, "Please refund order o-1.")
```

A stop comes back to the model as the tool's output, a short message it can
act on, and the run goes on. Calls made outside `ledger.run(...)` are refused
and end the run with an error, so a missing run is never silent.

## Keys and credentials

Declare `idempotency_key` for a `native` or `probe` spec, and `credentials`
for a spec that lists credentials, as ordinary parameters with a default:

```python
crm_spec = ToolSpec(name="crm.update", effect="write", credentials=("crm",))


@guarded_function_tool(ledger, crm_spec)
def crm_update(contact: str, credentials: dict[str, str] | None = None) -> str:
    """Update a CRM contact."""
    return crm.update(contact, token=credentials["crm"])
```

The SDK never sees these parameters: they are left out of the function it
wraps, so they are not in the schema (strict mode works), not in the input it
parses, and not in its logs. The ledger hands the values to your function
when it runs it. A tool's result and errors are scrubbed of the credential
values before the SDK sees them. A function that cannot take what its spec
needs is refused when the tool is built.

## Tool errors

The SDK normally turns a tool's exception into text for the model. Arbitr
does this after the ledger has recorded the failure, so the same call can run
again later instead of the error text being stored as its result.
`failure_error_function` works as in the SDK; the default never shows the
exception to the model. Pass `failure_error_function=None` to let errors end
the run.

To guard a `FunctionTool` you already have, build it with
`function_tool(..., failure_error_function=None)` and pass it to
`guard_function_tool(ledger, spec, tool)`. Such a tool receives the
idempotency key through the SDK's input; tools that need credentials must be
built with `guarded_function_tool`, and `guard_function_tool` refuses them.

## Testing without the API

`arbitr.testing.openai_agents.ScriptedModel` plays the model's side from a
script; `run_config()` also turns tracing off, so nothing is exported:

```python
from arbitr.testing.openai_agents import ScriptedModel

model = ScriptedModel([[("refund", {"order_id": "o-1", "amount": 25})], "Refunded."])
result = await Runner.run(agent, "Refund o-1", run_config=model.run_config())
model.tool_outputs()  # what each tool call returned to the model
```

See `examples/openai_agents_runner.py`.
