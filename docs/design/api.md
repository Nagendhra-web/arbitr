# Public API design

This page is the contract for Arbitr's Python API: what is public, what each
part promises, and how the parts fit. Everything not listed here is internal
and may change without notice. The three examples at the end are complete
programs; Arbitr's CI runs them.

## Design rules

- **One protocol.** Every way in ends in `Ledger.execute(spec, args, fn)` (or
  `aexecute`). The decorator and the framework adapters only translate a call
  into that and a stop back into the framework's tool result.
- **Stops are values for the model, not crashes.** A denied, waiting or
  unknown action raises an `ActionError`; adapters turn it into a tool result
  with `to_tool_message()`, so the agent reads it and goes on.
- **Setup mistakes are loud.** A call outside a run, or a tool that cannot
  take what the ledger injects, is refused with `RunContextError` or
  `TypeError`, never turned into a quiet message (the one exception is the
  Anthropic tool runner, which turns every tool error into a result; the
  tool still never runs).
- **The model never controls safety inputs.** `idempotency_key` and
  `credentials` are injected by the ledger. They are removed from every schema
  the model sees and from every argument set the model sends.
- **No `Any` in public signatures.** Options passed through to a framework are
  typed with a `TypedDict` that mirrors the framework's own parameters. Where
  a framework type is generic (`Command[Any]`, `BetaFunctionTool[Any]`), the
  `Any` is the framework's.

## Top-level names

`from arbitr import ...`, loaded on first use so `import arbitr` stays cheap:

| Name | What it is |
| --- | --- |
| `Ledger` | The ledger and gate; its public methods are listed below. |
| `ToolSpec` | What a tool does to the world (`effect`) and how it is retried safely (`idempotency`: `native`, `probe` or `none`). |
| `guard` | The decorator for plain functions and coroutines. |
| `ArbitrError` | The base of every error Arbitr raises. |
| `RunContextError` | A setup mistake: a tool call outside `ledger.run(...)`, or a run resumed for another principal or agent. |
| `ActionError` | The base of every stop. Each has `to_tool_message()`. |
| `ActionDenied`, `ApprovalPending`, `ApprovalRejected`, `ActionScheduled`, `InFlight`, `UnknownOutcome`, `LedgerUnavailable` | The stops. |

### `Ledger`

Opening and running:

| Method | What it does |
| --- | --- |
| `Ledger.open(path, policy, *, key, **options)` | Open (or create) the ledger at `path`. `options` are `LedgerOptions` (below). |
| `Ledger.from_config(path=None, **options)` | Open the ledger described by `arbitr.yaml` (or `path`, or the file in `ARBITR_CONFIG`), with its policy, key, credentials, approvers and protected paths. `options` win over the config. |
| `close()` | Close every connection. A closed ledger cannot reopen. |
| `run(principal, agent_id, *, run_id=None, scope=None, scopes=(), mode=None, resume=False, metadata=None)` | A context manager: the tool calls inside belong to this run. |
| `execute(spec, args, fn, *, step_id=None, idempotency_key=None)` | Run one tool call through the gate, at most once. |
| `aexecute(...)` | The async form of `execute`. |

Approvals:

| Method | What it does |
| --- | --- |
| `approve(approval_id, *, approver, roles=(), note=None)` | Approve a request; the action runs on the agent's next call. |
| `reject(approval_id, *, approver, roles=(), note=None)` | Reject a request; the action never runs. |
| `approval(approval_id)`, `approvals(status=None)`, `approval_votes(approval_id)` | Read approval requests and their votes. |
| `approval_card(approval_id)` | The readable card an approver sees. |
| `approval_links(approval_id, *, approver, base_url, roles=())` | Signed one-tap approve and reject links for one approver. |
| `decide_by_link(token, *, note=None)` | Apply the decision in a signed link, once. |
| `expire_approvals()` | Expire requests past their time and approvals never used in time. |

Recovery and scheduling:

| Method | What it does |
| --- | --- |
| `recover_stale()` | Mark every action whose worker's lease ran out as UNKNOWN (run it on startup). |
| `stale_count()` | How many running actions have an expired lease right now. |
| `cancel(intent_id, *, reason="cancelled")` | Cancel a scheduled action inside its cancel window. |
| `run_due(tools)` | Run every scheduled action whose cancel window has passed. |

Reads and audit:

| Method | What it does |
| --- | --- |
| `runs(*, limit=50)`, `run_record(run_id)` | Recent runs, or one run. |
| `find_intents(*, run_id=None, state=None, tool=None, since=None, limit=100)` | Actions matching every filter, newest first. |
| `intent(intent_id)`, `intent_by_key(key)`, `receipt(intent_id)`, `preview_of(intent_id)` | One action, its receipt and its preview. |
| `intent_events(intent_id)`, `events()` | Audit events for one action, or all of them. |
| `verify()` | Check the audit chain and every record against it. |
| `export_text()` | Everything stored, as text, for audits and secret checks. |

`LedgerOptions` (`from arbitr.executor import LedgerOptions`) are the keyword
settings of `open` and `from_config`: `worker_id`, `lease_ttl`,
`approval_ttl`, `credentials`, `notifier`, `protected_paths`,
`preview_context` and `preview_timeout`. Three more, `clock`, `heartbeat`
and `on_step`, are test seams for deterministic simulation and crash
injection; leave them at their defaults outside tests.

### What the model reads for each stop

| Stop | Message (abridged) |
| --- | --- |
| `ActionDenied` | `Blocked by policy '<rule>': <reason> Do not retry. Ask the user.` |
| `ApprovalPending` | `This action needs human approval (request <id>): <reason> It has not run. ...` |
| `ApprovalRejected` | `This action was not approved (...). Do not retry. Ask the user.` |
| `ActionScheduled` | `Scheduled: this action will run at <time> unless someone cancels it first. ...` |
| `InFlight` | `This exact action is already running. Do not retry; wait for it to finish.` |
| `UnknownOutcome` | `The action may or may not have happened, and running it again could do it twice. ...` |
| `LedgerUnavailable` | `The action did not run because the safety ledger is unavailable. Try again later.` |

## `guard`

```text
guard(ledger: Ledger | Callable[[], Ledger], spec: ToolSpec, *, step_id: str | None = None)
```

Bound arguments with defaults filled in are the intent's arguments. A repeat
of a call that succeeded returns the stored receipt (redacted JSON). Refused
when decorating: positional-only parameters, `*args`, a native or probe tool
without `idempotency_key`, a tool that declares credentials without
`credentials`, and a fixed `step_id` on a tool that allows duplicates.

## Adapters

| Module | Entry points | Framework hook |
| --- | --- | --- |
| `arbitr.integrations.anthropic` | `guard_tool`, `guard_tools`, `tool_results`, `atool_results`, `GuardedTool`, `GuardedAsyncTool` | the SDK's builtin tool classes, so the tool runner calls them unchanged |
| `arbitr.integrations.openai_agents` | `guarded_function_tool`, `guard_function_tool`, `FunctionToolOptions` | `FunctionTool.on_invoke_tool` |
| `arbitr.integrations.langgraph` | `guarded_tool_node`, `ArbitrGate`, `ToolNodeOptions` | `ToolNode(wrap_tool_call=..., awrap_tool_call=...)` |

Shared promises: a tool without a spec counts as a `write`; tools that
cannot take what the ledger injects are refused when wrapped; a tool error
is recorded as a failure (or as an unknown outcome when it may have acted)
before the framework turns it into text; and a repeat returns the stored
receipt. See the [integration pages](../integrations/index.md) for each
framework's details, including how LangGraph threads map to runs.

### For integration authors

Building an adapter for another framework uses these, and they are public:

| Name | What it is |
| --- | --- |
| `arbitr.guarding.INJECTED` | The parameter names the ledger fills in (`idempotency_key`, `credentials`). |
| `arbitr.guarding.require_injected(name, spec, accepted)` | Refuse, at wrap time, a tool that cannot take what its spec needs injected. |
| `arbitr.executor.scrub_injected(value, injected)` | Remove injected credential values from a result, as the ledger does to receipts. Use it when the framework sees a result before the ledger does. |
| `arbitr.executor.scrubbed_error(exc, injected)` | The same for an exception: scrubbed, or replaced when it cannot be. |
| `arbitr.core.errors.AmbiguousToolError` | Raise it when a tool may have acted in a way that cannot be checked; the ledger records the outcome as unknown. |

## `arbitr.testing`

A pytest plugin (`arbitr_policy`, `arbitr_ledger`, `arbitr_run` fixtures),
assertions (`assert_no_effect`, `assert_denied`, `assert_needs_approval`,
`assert_exactly_once`, `assert_not_run`, all taking the run first), fakes
(`FakeTool`, `FakePayments`, the `find_refund` probe), crash injection
(`crash_at`, `restart`, `SimulatedCrash`) and scripted models
(`arbitr.testing.anthropic.ScriptedClaude`,
`arbitr.testing.openai_agents.ScriptedModel`,
`arbitr.testing.langgraph.ScriptedAgent`). See [Testing your agent](../testing.md).

## Examples

### A refund tool behind the decorator

```python
import secrets
import tempfile
from pathlib import Path

from arbitr import ApprovalPending, Ledger, ToolSpec, guard
from arbitr.policy.schema import load_policy
from arbitr.testing import FakePayments

policy = load_policy("""
version: 1
default: { financial: allow }
rules:
  - id: big-refunds
    when: { tool: payments.refund, args: [{ path: "$.amount", op: gt, value: 100 }] }
    then: require_approval
    reason: Refunds over 100 need a human.
""")
payments = FakePayments()
spec = ToolSpec(name="payments.refund", effect="financial", idempotency="native")

with tempfile.TemporaryDirectory() as folder:
    with Ledger.open(Path(folder) / "arbitr.db", policy, key=secrets.token_bytes(32)) as ledger:

        @guard(ledger, spec)
        def refund(order_id: str, amount: float, *, idempotency_key: str | None = None) -> dict:
            return payments.refund(order_id, amount, idempotency_key=idempotency_key)

        with ledger.run(principal="alice@example.com", agent_id="support-bot"):
            refund("o-1", 25)
            refund("o-1", 25)  # the agent retried: the receipt comes back
            try:
                refund("o-2", 500)
            except ApprovalPending as waiting:  # a person approves it (CLI, link or code)
                ledger.approve(waiting.approval_id, approver="bob@example.com")
            refund("o-2", 500)  # approved for exactly these arguments: it runs now

assert payments.count() == 2
```

### Claude with the tool runner

```python
import secrets
import tempfile
from pathlib import Path

from anthropic import beta_tool

from arbitr import Ledger, ToolSpec
from arbitr.integrations.anthropic import guard_tools
from arbitr.policy.schema import load_policy
from arbitr.testing.anthropic import ScriptedClaude

policy = load_policy("""
version: 1
rules:
  - id: no-destructive-sql
    when: { tool: db.execute, effect: destructive }
    then: deny
    reason: Agents may not run destructive SQL.
""")
statements: list[str] = []


@beta_tool
def run_sql(sql: str) -> str:
    """Run a SQL statement on the orders database."""
    statements.append(sql)
    return "ok"


# A scripted Claude: offline, no key. Pass anthropic.Anthropic() in real use.
claude = ScriptedClaude([[("run_sql", {"sql": "DELETE FROM orders"})], "I could not do that."])
with tempfile.TemporaryDirectory() as folder:
    with Ledger.open(Path(folder) / "arbitr.db", policy, key=secrets.token_bytes(32)) as ledger:
        tools = guard_tools(
            ledger, [run_sql], {"run_sql": ToolSpec(name="db.execute", effect="write")}
        )
        with ledger.run(principal="alice@example.com", agent_id="ops-bot"):
            runner = claude.client().beta.messages.tool_runner(
                model="claude-opus-5-5",
                max_tokens=16000,
                tools=tools,
                messages=[{"role": "user", "content": "Clear out the old orders."}],
            )
            replies = list(runner)

(result,) = claude.tool_results()
assert result["is_error"] is True
assert "no-destructive-sql" in str(result["content"])
assert statements == []  # the DELETE never reached the database
```

### A LangGraph thread per conversation

```python
import secrets
import tempfile
from pathlib import Path
from typing import Annotated

from langchain_core.tools import InjectedToolArg, tool

from arbitr import Ledger, ToolSpec
from arbitr.integrations.langgraph import guarded_tool_node
from arbitr.policy.schema import load_policy
from arbitr.testing import FakePayments
from arbitr.testing.langgraph import ScriptedAgent, tool_messages

payments = FakePayments()


@tool
def refund(
    order_id: str,
    amount: float,
    idempotency_key: Annotated[str | None, InjectedToolArg] = None,
) -> str:
    """Refund an order."""
    made = payments.refund(order_id, amount, idempotency_key=idempotency_key)
    return f"refunded {made['refund_id']}"


def node_for(ledger: Ledger, signed_in_user: str):
    # The principal comes from your server's own login, never from the graph
    # config: a client that can send config could otherwise act as anyone.
    return guarded_tool_node(ledger, [refund], {"refund": spec}, principal=signed_in_user)


policy = load_policy("version: 1\ndefault: { financial: allow }\n")
spec = ToolSpec(name="payments.refund", effect="financial", idempotency="native")
with tempfile.TemporaryDirectory() as folder:
    with Ledger.open(Path(folder) / "arbitr.db", policy, key=secrets.token_bytes(32)) as ledger:
        for _ in range(2):  # the same conversation, picked up twice
            node = node_for(ledger, signed_in_user="alice@example.com")
            agent = ScriptedAgent([[("refund", {"order_id": "o-1", "amount": 25})], "Done."])
            state = agent.graph(node).invoke(
                {"messages": [("user", "Refund o-1")]},
                {"configurable": {"thread_id": "conversation-7"}},
            )
            assert tool_messages(state)[0].content == "refunded re_000001"
        (run,) = ledger.runs()
        assert run.run_id == "thread-langgraph-conversation-7"

assert payments.count() == 1  # one refund across both turns of the thread
```
