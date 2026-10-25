<p align="center">
  <img src="docs/assets/logo-light.svg" alt="Arbitr" width="240">
</p>

<p align="center">The final say on every action your AI agents take, in every product you build.</p>

Arbitr is a write-ahead ledger and deterministic gate that sits between your AI agents and the real world.

- **Blocks dangerous actions before they run.** Rules you write decide, not a model.
- **Makes retries safe, so nothing happens twice.** Every call has an idempotency key and a recovery path.
- **Records every action with a tamper-evident receipt.** Who asked, what ran, what was decided and why.

> Status: pre-alpha. Nothing here is usable yet.

## How it works

<img src="docs/assets/architecture-light.svg" alt="Arbitr architecture: AI agents call tools through an integration layer (a @guard decorator, an Anthropic tool-use helper, an OpenAI Agents SDK adapter, a LangGraph tool node, an MCP proxy or an HTTP API). Every call passes five stages in the Arbitr core: canonicalize and build the intent, write it to the ledger, decide with a deterministic gate (allow, deny or require approval), check the approval, and execute once in effect against databases, cloud, payments, email, GitHub or the shell. A redactor, a compensator and a tamper-evident audit chain support the core, which stores to SQLite or Postgres and feeds a CLI, a local dashboard, a shadow report and OpenTelemetry spans." width="100%">

Every tool call your agent makes becomes an action intent, and goes through five steps:

1. **Canonicalize.** The call is turned into canonical JSON with an intent hash and an idempotency key, so the same action always looks the same.
2. **Write ahead.** The intent is written to the ledger before anything runs, so after a crash Arbitr knows what was attempted.
3. **Decide.** A deterministic gate checks your policy rules, resource tags, budgets and run taint, and answers allow, deny or require approval. No LLM is in the decision.
4. **Approve when it matters.** An approval is bound to the exact call it was given for, so it cannot be reused for different arguments.
5. **Execute once.** Leases, idempotency keys, recovery probes and receipts make sure a side effect happens at most once, even if the agent crashes and retries.

Secrets are redacted before anything is stored, every state change is recorded in a tamper-evident audit chain, and actions that declare how can be compensated (undone). A shadow mode records what would have been blocked without blocking anything, so you can try Arbitr on real traffic with no risk.

## Development

CI runs on your machine, not on GitHub Actions.

```
make setup      # install dependencies and git hooks
make ci-fast    # lint, types, unit tests (under a minute)
make ci         # the full pipeline, required before every commit and push
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
