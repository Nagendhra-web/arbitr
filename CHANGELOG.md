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
