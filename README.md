# Arbitr

The final say on every action your AI agents take, in every product you build.

Blocks dangerous actions before they run. Makes retries safe, so nothing happens twice. Records every action with a tamper-evident receipt.

> Status: pre-alpha. Nothing here is usable yet.

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
