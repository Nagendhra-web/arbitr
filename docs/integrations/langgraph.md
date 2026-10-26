# LangGraph

`arbitr.integrations.langgraph` works with LangGraph 1.x and its prebuilt
`ToolNode`. Install it with `pip install "arbitr[langgraph]"`.

`guarded_tool_node` builds a `ToolNode` with Arbitr's gate in the node's own
hooks (`wrap_tool_call` and `awrap_tool_call`), so it works with
`graph.invoke` and `graph.ainvoke`.

```python
from typing import Annotated

from langchain_core.tools import InjectedToolArg, tool

from arbitr import Ledger, ToolSpec
from arbitr.integrations.langgraph import guarded_tool_node

ledger = Ledger.from_config()


@tool
def refund(
    order_id: str,
    amount: float,
    idempotency_key: Annotated[str | None, InjectedToolArg] = None,
) -> str:
    """Refund an order."""
    made = payments.refund(order_id, amount, idempotency_key=idempotency_key)
    return f"refunded {made['refund_id']}"


specs = {"refund": ToolSpec(name="payments.refund", effect="financial", idempotency="native")}
signed_in_user = request.user  # from your server's own login, never from graph config
builder.add_node("tools", guarded_tool_node(ledger, [refund], specs, principal=signed_in_user))
```

Mark `idempotency_key` and `credentials` with `InjectedToolArg`. The model
never sees them and LangChain callbacks never log them. ToolNode removes
injected arguments before a tool runs; Arbitr adds the ledger's values back
right before the real tool is called. A native or probe tool without an
`idempotency_key` parameter, a tool that declares credentials without a
`credentials` parameter, or either one left visible to the model, is refused
when the node is built.

A stop becomes an error `ToolMessage` with a message for the model, and the
graph keeps going.

What the model reads, the artifact and any state update a tool returns are
scrubbed of the credential values the ledger injected. LangChain callbacks
(tracing such as LangSmith) see a tool's output and errors inside the tool
call, so for a tool that gets credentials the scrubbing happens in the tool's
own function, before callbacks run. Such a tool must therefore be a
`StructuredTool` (what `@tool` makes); any other tool type that declares
credentials is refused when the node is built.

## Tool errors

The ledger sees every tool error as it happened, so it can tell a failure
from an unknown outcome. A timeout or a lost connection may mean the action
happened, so it ends as an unknown outcome: the model is told, and the call
is not run again on a retry. Other errors are recorded as failures, so the
call can run again. Then `handle_tool_errors` (with the same meaning as for
`ToolNode`: a bool, a message, a handler function, or exception types) turns
the error into a message for the model, or lets it end the graph.

## Runs, threads and who the agent acts for

If the graph runs inside `ledger.run(...)`, its tool calls belong to that run.
Otherwise each LangGraph thread is one ledger run, named
`thread-<agent_id>-<thread_id>`, for the node's `principal`:

```python
def handle(request):
    user = request.authenticated_user  # from your server's own login
    node = guarded_tool_node(ledger, tools, specs, principal=user)
    ...
    graph.invoke(state, {"configurable": {"thread_id": request.conversation_id}})
```

`principal` is a fixed name, or a function of the graph config for a value
your server put there. Take it from your server's own authentication. Never
read it from config a client can send: on LangGraph Platform, clients can set
`configurable`, so use the identity the platform's auth layer establishes. A call with no
run and no principal is refused. A thread keeps the principal and agent it
started with, and resuming it for anyone else is refused.

Within a thread, the same tool call with the same arguments returns the
first result instead of running again. A tool that returned a `Command`
(a state update) is not replayed; the model is told it already ran.

## Testing without a model

`arbitr.testing.langgraph.ScriptedAgent` is a graph node that plays the
model's side from a script, and `graph()` wires it to your tool node:

```python
from arbitr.testing.langgraph import ScriptedAgent, tool_messages

agent = ScriptedAgent([[("refund", {"order_id": "o-1", "amount": 25})], "Refunded."])
graph = agent.graph(guarded_tool_node(ledger, [refund], specs))
state = graph.invoke({"messages": [("user", "Refund o-1")]}, config)
tool_messages(state)  # the ToolMessages, in order
```

See `examples/langgraph_tool_node.py`.
