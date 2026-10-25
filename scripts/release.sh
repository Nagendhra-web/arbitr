#!/usr/bin/env bash
# Local release.
#   scripts/release.sh          real release to PyPI, GHCR, GitHub and npm
#   scripts/release.sh --test   TestPyPI and a test image tag, no tag, no GitHub release
#
# Step 1 (preflight checks) is implemented. Build, SBOM, signing and publishing
# are not built yet; until then the script stops after the checks with a clear
# message. It never publishes anything without every check passing.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MODE="release"
[ "${1:-}" = "--test" ] && MODE="test"

fail() { echo "release blocked: $1" >&2; exit 1; }

# 1. Preflight.
[ -z "$(git status --porcelain)" ] || fail "the working tree is not clean."
branch="$(git rev-parse --abbrev-ref HEAD)"
[ "$branch" = "main" ] || fail "releases are cut from main, not '$branch'."

version="$(sed -nE 's/^version = "([^"]+)"/\1/p' pyproject.toml | head -1)"
top="$(sed -nE 's/^## \[([^]]+)\].*/\1/p' CHANGELOG.md | grep -v -i '^unreleased$' | head -1)"
[ "$version" = "$top" ] || fail "pyproject version '$version' does not match the top CHANGELOG entry '$top'."

sha="$(git rev-parse HEAD)"
uv run --locked python scripts/check_release_record.py "$sha" \
  || fail "no passing make ci-docker record for HEAD on a clean tree. Run make ci-docker."

[ -f "ci-logs/release-check-${sha}.ok" ] || fail "make release-check has not passed for HEAD."

echo "Preflight checks passed for ${version} at ${sha} (${MODE} mode)."

# 2 to 9. Build, SBOM, sign, publish, image, tag, GitHub release, npm.
fail "build, signing and publishing steps are not built yet."
