# Anthropic

`arbitr.integrations.anthropic` works with the Anthropic Python SDK
(`anthropic` 2.x). Install it with `pip install "arbitr[anthropic]"`.

## With the tool runner

Define tools with the SDK's `@beta_tool` (or `@beta_async_tool`) and guard
them. The guarded tools are ordinary SDK tools, so the tool runner calls them
as usual. A stop becomes a tool result with `is_error: true` and a message
for Claude; the run goes on.

```python
import anthropic
from anthropic import beta_tool

from arbitr import Ledger, ToolSpec
from arbitr.integrations.anthropic import guard_tools

ledger = Ledger.from_config()
client = anthropic.Anthropic()


@beta_tool
def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
    """Refund an order.

    Args:
        order_id: The order to refund.
        amount: How much to refund.
    """
    made = payments.refund(order_id, amount, idempotency_key=idempotency_key)
    return f"refunded {made['refund_id']}"


specs = {"refund": ToolSpec(name="payments.refund", effect="financial", idempotency="native")}
tools = guard_tools(ledger, [refund], specs)

with ledger.run(principal="alice@example.com", agent_id="support-bot"):
    runner = client.beta.messages.tool_runner(
        model="claude-opus-5-5",
        max_tokens=16000,
        tools=tools,
        messages=[{"role": "user", "content": "Please refund order o-1."}],
    )
    for message in runner:
        print(message)
```

Every call must happen inside `ledger.run(...)`. Outside one the tool never
runs; because the tool runner turns any error a tool raises into a tool
result, Claude gets an error result that names the missing run.

`specs` maps tool names to specs; a tool without one counts as a `write`.
`guard_tool(ledger, spec, tool)` guards a single tool. The tool's input
schema sent to Claude has `idempotency_key` and `credentials` removed.

## In your own loop

If you write the loop yourself, pass the response content to `tool_results`
and send everything it returns back in one user message, as the API expects
for parallel tool calls:

```python
from arbitr.integrations.anthropic import tool_results

response = client.messages.create(
    model="claude-opus-5-5",
    max_tokens=16000,
    tools=[tool.to_dict() for tool in tools],
    messages=messages,
)
messages.append({"role": "assistant", "content": response.content})
messages.append({"role": "user", "content": tool_results(response.content, tools)})
```

`atool_results` is the async form and accepts sync and async tools together.
A tool Claude names that is not in the list is never run; it gets an error
result.

## Testing without the API

`arbitr.testing.anthropic.ScriptedClaude` is a real `anthropic.Anthropic`
client whose answers come from a script of turns, with no network:

```python
from arbitr.testing.anthropic import ScriptedClaude

claude = ScriptedClaude([[("refund", {"order_id": "o-1", "amount": 25})], "Refunded."])
client = claude.client()  # use it like any client
...
claude.tool_results()  # every tool_result block the agent sent back
```

See `examples/anthropic_tool_runner.py` and `examples/testing_kit/`.
