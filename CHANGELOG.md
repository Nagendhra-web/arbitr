# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Core ledger:
  - Canonical JSON (RFC 8785), tested against the RFC's published vectors.
    Large integers are accepted only when they survive the round trip exactly,
    so two different arguments can never share a hash.
  - Action intents built from a private snapshot of the arguments, with an
    intent hash and an idempotency key; tool specifications.
  - An explicit intent state machine, checked against its TLA+ model.
  - SQLite storage: WAL with full sync, versioned forward-only migrations, safe
    concurrent opening, and compare-and-set state changes fenced on the attempt
    number and lease owner. Every storage failure is reported as a
    `StorageError`, so callers can fail closed.
  - A tamper-evident audit chain covering each event and the intent and run it
    belongs to. `verify` reports the first broken link and checks every intent
    record against its events. JSON lines export.
  - Redaction inside storage with keyed markers: fields named like secrets in
    any spelling (`password`, `clientSecret`, `Proxy-Authorization`, ...),
    tool-specific paths, API keys and tokens, private keys, JWTs, `Bearer` and
    `Basic` credentials, passwords in URLs, and card numbers as text or as
    integers. A secret with no recognizable shape and no label in free text
    cannot be detected; put secrets in named fields.
- Policy engine:
  - A YAML policy format with a published JSON Schema. The loader refuses
    duplicate keys and unsafe tags, and any malformed file is reported as a
    `PolicyError`. Regular expressions in rules run on RE2, a linear-time
    engine, so no argument can make a rule slow to match.
  - A pure, deterministic gate: deny beats require approval beats allow, safe
    defaults per effect, time windows, argument conditions, shadow mode with
    rules that are always enforced, and decision reasons taken only from the
    policy text. A run can make the gate stricter but never looser than the
    policy. `Decision.explain()` lists every matching rule and why the winner
    won.
  - Budgets per principal, agent, run, tool, day or hour (UTC), reserved
    atomically in the ledger so concurrent calls and processes never overspend,
    and checked against the audit chain by `verify`.
  - Run scope manifests: a run can declare its task, allowed tools, resource
    tags, highest effect and spend limit. Actions outside the scope need
    approval (or are denied, by policy), and a sub-agent cannot widen its
    parent's scope or run in shadow mode under an enforcing parent.
  - Run taint: reading untrusted input or private data marks the run, every
    run it spawns and every run above it, so a sub-agent cannot hide what it
    read from its parent. Used by rules about the lethal trifecta.
  - Outbound data loss prevention for messages that leave the system: secrets,
    card numbers, phone numbers and email addresses, national ID plugins, and
    copies of private text the run read earlier.
  - A resource registry. Extractors find tables, databases, paths, URLs, GitHub
    repositories, email recipients, Kubernetes objects and git remotes in tool
    arguments, and policies tag them. SQL and shell extractors raise an
    action's effect to destructive when they see `DROP`, `DELETE` without
    `WHERE`, `rm -rf`, `terraform destroy`, `git push --force` and similar,
    including commands hidden in `sh -c`, substitutions, pipes into a shell and
    dynamic SQL. Effects are only ever raised. Tested against about 400 sample
    commands and statements, with and without the optional SQL parser.
  - `arbitr policy test` runs case tables against a policy, `arbitr policy
    lint` warns about rules that never match, shadowed rules and unprotected
    destructive tools, and `arbitr policy schema` prints the JSON Schema.
  - Ten policy packs, each with its own case table: databases, filesystem,
    git, cloud-cli, kubernetes, payments, email-and-messaging, github,
    mcp-basics and lethal-trifecta. A policy includes packs by name and can
    replace or exclude any pack rule.
- Executor:
  - `Ledger.execute` and `aexecute` run every tool call through the ledger and
    the gate. The decision (with its budget reservations) and the EXECUTING
    record with a lease are committed before the tool runs; if the ledger
    cannot be written, the tool does not run.
  - Leases on the database clock with a heartbeat, renewed right before a late
    call. Fences on attempt and lease owner refuse late writes from a worker
    that lost its lease.
  - Recovery by idempotency mode: `native` tools re-run with the same
    idempotency key, `probe` tools ask the service whether the action
    happened, and `none` tools stay UNKNOWN until the policy's `on_unknown`
    rule or a human decides. A repeated call returns the stored receipt.
    `recover_stale()` resolves expired work after a restart.
  - Cancel windows: a rule can say `then: delay 60s`. The action is scheduled
    with its budget reserved, `cancel()` stops it and gives the budget back,
    and `run_due()` runs due actions through the normal path, including ones a
    crashed scheduler left behind.
  - Budget reservations are recorded per action, so a failure or a cancel
    gives back exactly what that action reserved. A run's spend limit is
    charged to the run and every run above it.
  - Credentials are injected only after the gate allows the action. They are
    never stored. Their values, and their common encodings, are scrubbed from
    tool results, errors, error causes and traceback frames before the ledger
    or the agent sees them; an object that carries one (in an attribute, a
    slot or a closure) is replaced by its scrubbed text. An agent that calls a
    tool from its own except block keeps its own error untouched.
  - Proven by a fault-injection matrix that kills a real worker process at
    every step for every idempotency mode, races of 50 threads and 8 processes
    on one key, a TLA+ model of the protocol checked with TLC, and 2,000
    deterministic simulation seeds that drive the real executor with crashes
    at every step.
  - A rule condition, `resource_count_gt`, that counts distinct resources of
    one kind; the messaging pack uses it to count recipients across to, cc and
    bcc.
- Repository scaffold, packaging with optional extras, local CI pipeline
  (`make ci`, `make ci-fast`, `make ci-docker`, `make act`), pinned CI Docker
  image, Postgres compose file for tests, git hooks that enforce owner
  authorship, commit message rules and push approval, manual-only GitHub
  workflows, and TLA+ and deterministic simulation skeletons.

### Fixed

- A spend amount given as true or false is outside a run's spend limit
  instead of being checked as 1 and never charged.
- A retried action that never had its cancel window needs approval instead of
  running at once.
- The messaging pack also limits recipient lists of more than 50 directly, so
  tools with their own resource extractor are covered.
- `gh api` paths are decoded and normalized before policy matching, so
  doubled, trailing or encoded slashes and dot segments no longer slip past
  path rules.
- CI records no longer overwrite each other (one file per run
  kind), PENDING can only come from the pending list, skips fail CI, the
  push guard requires a clean tree and HEAD as the pushed commit, identity
  checks cover emails and environment overrides, the em dash check fails
  closed, TLC keeps deadlock checking with a 2 minute limit, and `make act`
  keeps its log.
