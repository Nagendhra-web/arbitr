#!/usr/bin/env bash
# Migration upgrade test: create a database with the
# previous tagged release, run its bench, upgrade to HEAD, run verify and the
# bench again. Not built yet. Until then it fails loudly so release-check
# cannot pass by accident.
set -euo pipefail
echo "upgrade_test.sh: not built yet. release-check cannot pass without it." >&2
exit 1
