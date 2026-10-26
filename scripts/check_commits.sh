#!/usr/bin/env bash
# Check every commit since the last tag (or all commits when there is no tag):
# owner name and email as author and committer, and the commit message rules.
# With no commits at all there is nothing to check; the
# caller (scripts/ci.sh) decides how to report that.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/owner.sh
. "$here/lib/owner.sh"

if ! git rev-parse --verify -q HEAD >/dev/null; then
  echo "No commits yet, nothing to check."
  exit 0
fi

if last_tag="$(git describe --tags --abbrev=0 2>/dev/null)"; then
  range="${last_tag}..HEAD"
else
  range="HEAD"
fi

# Commits made outside the local hooks (an edit in GitHub's web editor) are
# listed with a reason. They must still be authored with the owner's email;
# only the name, committer and message checks are skipped for them.
exceptions="$(git rev-parse --show-toplevel)/scripts/commit-exceptions.txt"
excepted() {
  [ -f "$exceptions" ] && grep -qE "^$1([[:space:]]|$)" "$exceptions"
}
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
bad=0
count=0
while read -r sha; do
  count=$((count + 1))
  IFS=$'\t' read -r an ae cn ce < <(git log -1 --format='%an%x09%ae%x09%cn%x09%ce' "$sha")
  if excepted "$sha"; then
    if [ "${ae,,}" != "$ARBITR_OWNER_EMAIL" ]; then
      echo "$sha: listed in commit-exceptions.txt but not authored with the owner's email" >&2
      bad=1
    fi
    continue
  fi
  if [ "${an,,}" != "$ARBITR_OWNER_NAME" ] || [ "${cn,,}" != "$ARBITR_OWNER_NAME" ]; then
    echo "$sha: author \"$an\" / committer \"$cn\" is not $ARBITR_OWNER_NAME" >&2
    bad=1
  fi
  if [ "${ae,,}" != "$ARBITR_OWNER_EMAIL" ] || [ "${ce,,}" != "$ARBITR_OWNER_EMAIL" ]; then
    echo "$sha: author email \"$ae\" / committer email \"$ce\" is not the owner's email" >&2
    bad=1
  fi
  git log -1 --format='%B' "$sha" > "$tmp"
  if ! bash "$here/check_commit_msg.sh" "$tmp"; then
    echo "$sha: commit message rejected (see above)" >&2
    bad=1
  fi
done < <(git rev-list "$range")

[ "$bad" -eq 0 ] || exit 1
echo "Checked $count commits in $range: owner authorship and messages are clean."
