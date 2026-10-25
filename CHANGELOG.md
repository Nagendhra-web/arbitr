# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Repository scaffold, packaging with optional extras, local CI pipeline
  (`make ci`, `make ci-fast`, `make ci-docker`, `make act`), pinned CI Docker
  image, Postgres compose file for tests, git hooks that enforce owner
  authorship, commit message rules and push approval, manual-only GitHub
  workflows, TLA+ and deterministic simulation skeletons, senior engineer
  review agent and `/autopilot` command.

### Fixed

- CI records no longer overwrite each other (one file per run
  kind), PENDING can only come from the pending list, skips fail CI, the
  push guard requires a clean tree and HEAD as the pushed commit, identity
  checks cover emails and environment overrides, the em dash check fails
  closed, TLC keeps deadlock checking with a 2 minute limit, and `make act`
  keeps its log.
