# Integrations

Each integration is thin: it turns a framework's tool call into
`ledger.execute(spec, args, fn)` and turns a stop (denied, waiting for
approval, outcome unknown) into a tool result the model can read and act on.
The agent keeps running; the action simply did not happen.

| Framework | Use | Page |
| --- | --- | --- |
| Plain Python | `@guard(ledger, spec)` | [Decorator](decorator.md) |
| Anthropic SDK | `guard_tools(ledger, tools, specs)` with the tool runner, or `tool_results(...)` in your own loop | [Anthropic](anthropic.md) |
| OpenAI Agents SDK | `@guarded_function_tool(ledger, spec)` in place of `@function_tool` | [OpenAI Agents](openai-agents.md) |
| LangGraph | `guarded_tool_node(ledger, tools, specs)` in place of `ToolNode(tools)` | [LangGraph](langgraph.md) |
| MCP clients (Claude Code, Cursor, ...) | `arbitr mcp-proxy` in front of an MCP server | [MCP proxy](mcp-proxy.md) |

Every example in `examples/` runs offline with a scripted model, so you can
try them without an API key. To test your own agent the same way, see
[Testing your agent](../testing.md).

## What every integration does the same way

**A tool call needs a run.** Calls happen inside `ledger.run(principal=...,
agent_id=...)`, which says who the agent acts for. LangGraph can also take
the run from the graph's thread (see its page). A call with no run is
refused before anything runs.

**Every tool has a spec.** A `ToolSpec` says what the tool does to the world
(`read`, `write`, `external_comm`, `financial`, `destructive`) and how it can
be retried safely. A tool you did not give a spec counts as a `write`, so
nothing reaches the world unclassified. Arbitr also reads the arguments: SQL
that drops a table or a shell command that deletes files counts as
destructive whatever the spec says.

**The model never chooses the idempotency key.** `idempotency_key` and
`credentials` are filled in by the ledger when the tool runs. They are
removed from the schema the model sees and from the arguments it sends. A
model that could set the key could make a retry look like a new action.

**A repeated call returns the first result.** When the model calls the same
tool with the same arguments again in the same run, the stored receipt comes
back and the tool does not run again. Receipts are stored as redacted JSON,
so return plain data (text, numbers, lists, dicts) from your tools.

**Tool errors stay tool errors.** An error from the tool itself is recorded
as a failure, so the same call can run again later, and the model sees the
error the way the framework normally shows it.

**What the model reads.** Stops come back as short plain-English messages
written for the model, for example:

```text
Blocked by policy 'no-destructive-sql': Agents may not run destructive SQL. Do not retry. Ask the user.
```

The MCP proxy works the same way, with one difference: it runs as its own
process, so the run is one per client connection and the principal comes
from the config (or, over HTTP, from the client's token).
