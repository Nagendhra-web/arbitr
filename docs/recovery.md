# Recovery

Arbitr writes to the ledger before a tool runs, so a crash at any point leaves
a record that says how far the call got. This page explains what happens to
that record afterwards.

## The commit points

Every call through `Ledger.execute` makes these commits, in order:

1. **Decision.** The intent is stored, the gate decides, and any budget the
   action needs is reserved against the intent. The state becomes APPROVED,
   PENDING_APPROVAL, DENIED or SCHEDULED.
2. **Executing.** The state becomes EXECUTING with a new attempt number and a
   lease owned by this worker. The lease expiry uses the database clock, and a
   background thread extends it while the tool runs.
3. **Result.** The tool ran: SUCCEEDED with a receipt, FAILED (budgets given
   back), or UNKNOWN when the error leaves it unclear whether the tool acted
   (timeouts, lost connections, interrupts).

The tool is called only after commit 2. If the ledger cannot be written, the
call raises `LedgerUnavailable` and the tool does not run.

## After a crash

A worker that dies while a tool runs leaves the intent EXECUTING. Its lease
runs out, and from then on any worker may take it over. The fences on every
write (expected state, attempt number and lease owner) refuse late writes
from the old worker.

Call `ledger.recover_stale()` when a worker starts. It marks every EXECUTING
intent with an expired lease as UNKNOWN, and reports approved actions that
never started because their worker stopped between the two commits. The next call with the same
idempotency key then resolves it according to the tool's `idempotency` mode:

| Mode | What recovery does |
| ---- | ------------------ |
| `native` | Runs the tool again with the same `idempotency_key`. The service returns the first result instead of acting twice. |
| `probe` | Calls the tool's probe to ask the service whether the action happened. Found: the intent becomes SUCCEEDED with a receipt marked `probe`. Not found: the tool runs again. A failing probe leaves it UNKNOWN. |
| `none` | Follows the policy's `on_unknown` setting: `require_approval` (the default) asks a human, `fail` records FAILED, and `retry` runs again only for tools marked `allow_duplicates`. An action recorded as FAILED after an unknown outcome may have acted, so it is never run again on its own. |

Native and probe tools receive the key as an `idempotency_key` keyword
argument. A probe tool must store it with the side effect so its probe can
find it.

A repeated call whose intent already SUCCEEDED returns the stored receipt and
does not run the tool. Two workers racing on one key never both run it: one
wins the EXECUTING commit and the other gets `InFlight`.

## Leases

A lease is only as safe as its length. The worker renews it right before the
call if time has passed since it was taken (for example, during a slow
credential fetch), and refuses to call if another worker took over. While the
tool runs, a heartbeat renews it every third of its life and retries if the
database is briefly unavailable.

A call that is already running cannot be stopped. If the heartbeat cannot
renew the lease for a whole lease lifetime, another worker may take the action
over while the first call is still in flight. For `probe` and `none` tools,
set `lease_ttl` well above the longest database outage you expect.

## Cancel windows

A rule can delay an allowed action:

```yaml
- id: hold-bulk-email
  when: { tool: email.send_bulk }
  then: delay 60s
  reason: Bulk email waits a minute so someone can cancel it.
```

Durations are whole seconds, minutes or hours (`delay 90`, `delay 5m`,
`delay 2h`), at most 24 hours. Deny and require_approval beat a delay; among
delays, the longest wins. In shadow mode a delay is recorded but not applied.

The action is committed as SCHEDULED with its budget reserved, and the agent
gets `ActionScheduled` with the time it will run. Until then:

- `ledger.cancel(intent_id)` moves it to CANCELLED and gives its budget back.
  It raises `StaleStateError` once the action has started.
- `ledger.run_due(tools)` is the scheduler. Call it on a timer with a map from
  tool name to `(ToolSpec, function)`. It runs each due action through the
  normal executor path, so leases, idempotency and recovery apply. It also
  recovers scheduled actions that a crashed scheduler left behind, because
  the agent will not call them again.

A delayed action must be stored with its real arguments so the scheduler can
run it. When redaction changed the arguments (for example, they hold an API
key), the action needs approval instead of a delay.
