# Threat model

The full threat model is being written. The core assumptions:

- The agent is untrusted. It can be prompt-injected and can call any tool with any arguments.
- The agent must not reach the ledger database, policy file or approval endpoints through its own tools.
- Approvals are bound to the exact intent hash. Replaying an old approval for new arguments fails.
- Policy files are data, not code.
- When the ledger is unavailable, actions do not run (fail closed).
