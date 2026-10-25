# Contributing

Thanks for helping. A few rules keep this project trustworthy.

1. Run `make setup` once. It installs dependencies and the git hooks.
2. Write tests first for anything in `core/`, `policy/`, `storage/` or the executor.
3. Run `make ci` before you push. CI runs locally, not on hosted runners.
4. Never bypass hooks with `--no-verify`.
5. Commit messages follow Conventional Commits, for example `fix(policy): reject empty rule ids`.
6. Write plain English in docs and messages. No em dashes.
