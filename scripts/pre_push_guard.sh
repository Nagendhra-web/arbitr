#!/usr/bin/env bash
# pre-push hook, first step. The push goes ahead only when:
#   1. the owner approved this push in chat and ARBITR_PUSH_APPROVED=1 is set
#      for this single command,
#   2. the working tree is clean (untracked files count), and
#   3. every commit being pushed is HEAD,
# so the `make ci` that runs next tests exactly the commits being pushed.
#
# The pushed sha comes from PRE_COMMIT_TO_REF or PRE_COMMIT_LOCAL_BRANCH (set
# by the pre-commit framework) or, when run as a plain git hook, from the refs
# on stdin. pre-commit checks only the first ref of a multi-ref push, so push
# one branch at a time.
set -euo pipefail

if [ "${ARBITR_PUSH_APPROVED:-}" != "1" ]; then
  cat >&2 <<'MSG'
push blocked: ARBITR_PUSH_APPROVED=1 is not set.
Pushes need the owner's explicit approval for this specific push.
After approval, run: ARBITR_PUSH_APPROVED=1 git push ...
MSG
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "push blocked: the working tree has uncommitted or untracked changes." >&2
  echo "make ci must test exactly the commits being pushed. Commit or stash first." >&2
  exit 1
fi

head="$(git rev-parse HEAD)"
zero="0000000000000000000000000000000000000000"
pushed=()
if [ -n "${PRE_COMMIT_TO_REF:-}" ]; then
  pushed+=("$(git rev-parse "${PRE_COMMIT_TO_REF}^{commit}")")
elif [ -n "${PRE_COMMIT_LOCAL_BRANCH:-}" ]; then
  # pre-commit sets only the local ref when the push includes the root commit
  # (for example the first push to an empty remote).
  pushed+=("$(git rev-parse "${PRE_COMMIT_LOCAL_BRANCH}^{commit}")")
elif [ ! -t 0 ]; then
  while read -r _local_ref local_sha _remote_ref _remote_sha; do
    [ -n "${local_sha:-}" ] && [ "$local_sha" != "$zero" ] && pushed+=("$local_sha")
  done
fi

if [ "${#pushed[@]}" -eq 0 ]; then
  echo "push blocked: cannot tell which commit is being pushed." >&2
  exit 1
fi
for sha in "${pushed[@]}"; do
  if [ "$sha" != "$head" ]; then
    echo "push blocked: pushing $sha, but HEAD is $head. Check out what you push, so CI tests it." >&2
    exit 1
  fi
done

echo "Push approved for this command. Running the full local CI on HEAD before pushing."
