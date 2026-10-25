# Formal models

TLA+ models of the Arbitr execution protocol, checked with TLC.

- `make formal` checks every `*.small.cfg` model (part of `make ci`).
- `make formal-large` checks every `*.large.cfg` model (part of `make release-check`).

`IntentLifecycle.tla` holds the intent transition list between the
`BEGIN TRANSITIONS` and `END TRANSITIONS` markers. The Python transition table
is tested against that list, so the two cannot drift.

Status: skeleton (state machine only). Still to come: leases, commit points,
crashes, concurrent workers, the three idempotency modes and recovery, with the
AtMostOnceEffect, NoSilentRetry, NoExecuteWithoutLedger and ApprovalBinding
invariants and the liveness property.
