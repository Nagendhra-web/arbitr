# Testing your agent

The testing kit lets you prove, in your own CI, that your agent cannot do
something dangerous: that it never drops a table, never refunds twice, and
always waits for a person when the policy says so.

Installing Arbitr adds a pytest plugin. It gives three fixtures:

- `arbitr_policy`: the policy to test with. By default, the file named by the
  `arbitr_policy` option in your pytest config (relative to the rootdir), or
  Arbitr's default policy. Override the fixture to return a `Policy`, a path
  or YAML text.
- `arbitr_ledger`: a throwaway ledger in the test's temporary folder.
- `arbitr_run`: a run on that ledger, active for the whole test. Pass it to
  the assertions.

The assertions, fakes and crash helpers are in `arbitr.testing`. Every code
block on this page is a complete test file, and Arbitr's own CI runs them.

## Assertions

```python
import pytest

from arbitr import ActionDenied, ToolSpec, guard
from arbitr.testing import FakeTool, assert_denied, assert_exactly_once, assert_no_effect


@pytest.fixture
def arbitr_policy():
    return """
version: 1
rules:
  - id: no-destructive-sql
    when: { tool: db.execute, effect: destructive }
    then: deny
    reason: Agents may not run destructive SQL.
"""


def test_the_agent_cannot_drop_tables(arbitr_ledger, arbitr_run):
    database = FakeTool(ToolSpec(name="db.execute", effect="write"), returns="ok")
    run_sql = guard(arbitr_ledger, database.spec)(database)

    run_sql(sql="SELECT 1")
    with pytest.raises(ActionDenied):
        run_sql(sql="DROP TABLE customers")

    assert_no_effect(arbitr_run, "destructive")
    assert_denied(arbitr_run, tool="db.execute", rule="no-destructive-sql")
    assert_exactly_once(arbitr_run, "db.execute", args={"sql": "SELECT 1"})
    assert database.calls == [{"sql": "SELECT 1"}]
```

| Assertion | Passes when |
| --- | --- |
| `assert_no_effect(run, effect)` | no action with that effect ran, or may have run |
| `assert_denied(run, tool=, rule=, args=)` | a matching action was denied, and it did not run |
| `assert_needs_approval(run, tool=, rule=, args=)` | a matching action is waiting for a person, and it did not run |
| `assert_exactly_once(run, tool, args=)` | the tool started exactly once and succeeded; retries that got the receipt back do not count |
| `assert_not_run(run, tool, args=)` | the tool never ran |

Effects are the ones Arbitr settled on after reading the arguments, so an
`rm -rf` through a tool declared as a `write` counts as destructive. `args`
matches calls whose arguments include those values. A failing assertion
lists the actions involved.

## Fakes

`FakeTool(spec, returns=..., raises=..., lose_response=...)` stands in for any
tool and records `calls`. With `lose_response=True` it acts and then fails
with `LostResponse`, as if the reply never arrived. `FakePayments` is a
payments service with optional native idempotency and a probe endpoint, the
same one Arbitr's own crash tests use. Its probe is
`arbitr.testing.fakes:find_refund` (put the service in
`ledger.probe_context["payments"]`).

## Crash injection

`crash_at(ledger, point)` makes the next tool call die at `point`, as if the
worker were killed: `"before_tool"` (the ledger already said it would run) or
`"after_tool"` (the tool acted, but its result was never recorded).
`restart(ledger)` then makes the ledger act as a new worker that starts after
the dead worker's lease ran out, so the same call goes through recovery.

```python
import pytest

from arbitr import ToolSpec, guard
from arbitr.testing import FakePayments, SimulatedCrash, crash_at, restart

REFUND = ToolSpec(name="payments.refund", effect="financial", idempotency="native")


@pytest.fixture
def arbitr_policy():
    return "version: 1\ndefault: { financial: allow }\n"


def test_a_refund_survives_a_crash(arbitr_ledger, arbitr_run):
    payments = FakePayments()

    @guard(arbitr_ledger, REFUND)
    def refund(order_id, amount, idempotency_key=None):
        return payments.refund(order_id, amount, idempotency_key=idempotency_key)

    with crash_at(arbitr_ledger, "after_tool"), pytest.raises(SimulatedCrash):
        refund("o-1", 25)
    restart(arbitr_ledger)
    refund("o-1", 25)  # recovery runs it again with the same key

    assert payments.count() == 1  # the service deduplicated: one refund
```

What recovery does depends on the tool: a `native` tool runs again with the
same key and the service deduplicates; a `probe` tool asks the service first;
a tool with no idempotency is not run again and raises `UnknownOutcome`, so a
person decides.

## Scripted models

To test a whole agent loop offline, use the scripted model for your
framework: `arbitr.testing.anthropic.ScriptedClaude`,
`arbitr.testing.openai_agents.ScriptedModel` or
`arbitr.testing.langgraph.ScriptedAgent`. Each plays the model's side from a
list of turns, so a test can make the model misbehave on purpose.
`examples/testing_kit/` is a complete suite for a sample support agent.
