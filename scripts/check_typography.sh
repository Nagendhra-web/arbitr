#!/usr/bin/env bash
# Fail if any tracked or new (not ignored) file contains a character the
# project's writing style rules out (listed below as escapes). With file
# arguments, check only those.
#
# grep exit codes are checked explicitly: 0 is a hit, 1 is clean, anything
# else (a grep error or crash) fails the check, so it can never fail open.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

ruled_out="$(printf '\342\200\224')"

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  mapfile -t files < <(git ls-files --cached --others --exclude-standard)
fi

found=0
checked=0
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  checked=$((checked + 1))
  out="$(grep -I -n -F -- "$ruled_out" "$f")"
  rc=$?
  case "$rc" in
    0) printf '%s\n' "$out" | sed "s|^|$f:|"; found=1 ;;
    1) ;;
    *) echo "typography check could not read $f (grep exit $rc). Failing closed." >&2; exit 2 ;;
  esac
done

if [ "$found" -ne 0 ]; then
  echo "The lines above use a character the writing style rules out." "Use a comma, a colon or a separate sentence instead." >&2
  exit 1
fi
echo "Typography ok in ${checked} files."
