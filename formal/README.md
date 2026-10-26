# Formal models

TLA+ models of the Arbitr execution protocol, checked with TLC.

- `make formal` checks every `*.small.cfg` model (part of `make ci`).
- `make formal-large` checks every `*.large.cfg` model (part of `make release-check`).

`IntentLifecycle.tla` holds the intent transition list between the
`BEGIN TRANSITIONS` and `END TRANSITIONS` markers. The Python transition table
is tested against that list, so the two cannot drift.

## IntentLifecycle

The intent state machine on its own: which state may follow which. It checks
that every move is in the transition list, that terminal states are final, and
that nothing executes before it was allowed or approved.

## ExecutionProtocol

The execution and recovery protocol of `src/arbitr/executor.py`, run by
several workers against one ledger and one external service. It models:

- one intent per idempotency key, with the args hash stored at insert;
- the three ledger commits: insert plus decision, EXECUTING with attempt + 1
  and a lease owner, then SUCCEEDED, FAILED or UNKNOWN fenced on the state,
  the attempt and the lease owner;
- the side effect as its own step on the service, between the second and the
  third commit, for each tool mode: `native` (the service dedupes by key),
  `probe` (the service records the key so a probe can find it) and `none`;
- the lease check right before the call: the worker renews its lease, fenced
  on the owner and the attempt, and stops without calling if it was lost;
- crashes at any step, lease expiry on an abstract clock, the recovery sweep,
  probes (both probe commits are fenced on the attempt the probe was asked
  about), every `on_unknown` policy (`require_approval`, `retry`, `fail`),
  human approval and resolution, and the scheduled cancel window;
- a `none` tool without duplicates that was ever UNKNOWN never runs again on
  its own, even from FAILED.

Invariants and properties:

- `AtMostOnceEffect`: a native or probe tool causes its side effect at most
  once per key.
- `NoSilentRetry`: a `none` tool causes a second side effect only after an
  explicit retry decision taken from UNKNOWN, and never when the tool does not
  allow duplicates.
- `NoExecuteWithoutLedger`: every call that reaches the service runs under an
  attempt whose EXECUTING commit happened first.
- `ApprovalBinding`: every call carries the args hash that was approved.
- `CancelledNeverRuns`: a CANCELLED intent never reached the service.
- `LegalTransitions`: every recorded state change is in the transition list
  of `IntentLifecycle.tla` (the model reuses it through `INSTANCE`).
- `TerminalIsFinal`: nothing leaves a terminal state.
- `Settles` (liveness, under weak fairness for workers, leases and the
  recovery sweep, and strong fairness for the scheduler): an EXECUTING or
  SCHEDULED intent always ends up SUCCEEDED, FAILED, UNKNOWN or CANCELLED.

Assumptions the model makes, each written in the module header:

- `LeaseOutlivesCall`: once a worker has confirmed its lease, the lease does
  not run out before the call has reached the service. A running call cannot
  be stopped, so the code cannot enforce this: the call must be shorter than
  the lease, or the heartbeats must keep the lease alive. Before the confirm,
  a lease can run out at any moment. Native tools do not need the assumption:
  their leases can run out at any moment and late calls are deduplicated.
  Without it, TLC finds a double effect for probe tools.
- A clean tool error (FAILED) means the side effect did not happen.
- A human who resolves an UNKNOWN intent checks the service first.
- Attempts are bounded by `MaxAttempts` so the state space is finite.

Known gap, on purpose:

- `Settles` starts from EXECUTING or SCHEDULED. An intent left APPROVED by a
  worker that stopped between its two commits is not forced forward: running
  it needs the caller's arguments and function, which only the next call with
  the same key (or a future worker process that holds them) can supply. The
  code reports such intents from `recover_stale()`, and the model keeps them
  out of the liveness property rather than pretending they settle.

Two more paths, both in the code and in the model:

- A retry after a clean failure that the policy now holds for a human goes
  back to PENDING_APPROVAL (FAILED to PENDING_APPROVAL). For a `none` tool
  that was once UNKNOWN, a human approving that retry counts as an explicit
  decision to run it again.
- An approval whose action did not start in time goes stale (APPROVED to
  EXPIRED); the action never runs.

Only a new intent gets a cancel window: the gate decides a delay for a new
intent only, so a retry is never scheduled.

