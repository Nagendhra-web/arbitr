#!/usr/bin/env bash
# Run a command with the shared CI environment (tool paths on Windows hosts).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env.sh
. "$here/lib/env.sh"
exec "$@"
