#!/usr/bin/env bash
# pre-commit hook: the commit must be made as the project owner.
# Uses `git var`, which honours GIT_AUTHOR_*, GIT_COMMITTER_* and the config,
# so an environment override cannot slip past a config-only check.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/owner.sh
. "$here/lib/owner.sh"

ident_re='^(.*) <([^>]*)> [0-9]+ [-+][0-9]{4}$'
bad=0
for role in AUTHOR COMMITTER; do
  ident="$(git var "GIT_${role}_IDENT" 2>/dev/null)" || {
    echo "commit rejected: git cannot determine the ${role,,} identity. Set user.name and user.email." >&2
    exit 1
  }
  if ! [[ "$ident" =~ $ident_re ]]; then
    echo "commit rejected: cannot parse the ${role,,} identity \"$ident\"." >&2
    exit 1
  fi
  name="${BASH_REMATCH[1]}"
  email="${BASH_REMATCH[2]}"
  if [ "${name,,}" != "$ARBITR_OWNER_NAME" ]; then
    echo "commit rejected: ${role,,} name is \"$name\", expected \"$ARBITR_OWNER_NAME\" (check user.name and GIT_${role}_NAME)." >&2
    bad=1
  fi
  if [ "${email,,}" != "$ARBITR_OWNER_EMAIL" ]; then
    echo "commit rejected: ${role,,} email is \"$email\", expected the owner's email (check user.email and GIT_${role}_EMAIL)." >&2
    bad=1
  fi
done
exit "$bad"
