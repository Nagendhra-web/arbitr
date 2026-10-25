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
- Repository scaffold, packaging with optional extras, local CI pipeline
  (`make ci`, `make ci-fast`, `make ci-docker`, `make act`), pinned CI Docker
  image, Postgres compose file for tests, git hooks that enforce owner
  authorship, commit message rules and push approval, manual-only GitHub
  workflows, and TLA+ and deterministic simulation skeletons.

### Fixed

- CI records no longer overwrite each other (one file per run
  kind), PENDING can only come from the pending list, skips fail CI, the
  push guard requires a clean tree and HEAD as the pushed commit, identity
  checks cover emails and environment overrides, the em dash check fails
  closed, TLC keeps deadlock checking with a 2 minute limit, and `make act`
  keeps its log.
