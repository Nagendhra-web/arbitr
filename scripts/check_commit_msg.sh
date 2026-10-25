#!/usr/bin/env bash
# commit-msg hook: reject AI attribution and enforce Conventional Commits.
# Usage: check_commit_msg.sh <file containing the commit message>
#
# All matching uses bash itself, not grep, so a crashing or missing tool can
# never turn a rejection into a silent pass.
set -euo pipefail

msg_file="${1:?usage: check_commit_msg.sh <message file>}"
[ -r "$msg_file" ] || { echo "commit message rejected: cannot read $msg_file" >&2; exit 1; }

# Drop comment lines that git strips anyway.
msg=""
subject=""
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  [[ "$line" == "#"* ]] && continue
  msg+="$line"$'\n'
  if [ -z "$subject" ] && [ -n "${line//[[:space:]]/}" ]; then
    subject="$line"
  fi
done < "$msg_file"
lower="${msg,,}"

fail() { echo "commit message rejected: $1" >&2; exit 1; }

trailer_re=$'(^|\n)[[:space:]]*co-authored-by:'
if [[ "$lower" =~ $trailer_re ]]; then
  fail "it contains a Co-Authored-By trailer. Commits are authored by the owner only."
fi
if [[ "$lower" == *"generated with"* ]]; then
  fail "it contains a \"Generated with\" line. Remove tool attribution."
fi
if [[ "$lower" == *"noreply@anthropic.com"* ]]; then
  fail "it references noreply@anthropic.com. Remove tool attribution."
fi
link_re='claude\.(ai|com)/(code|chat|share|claude-code)'
if [[ "$lower" =~ $link_re ]]; then
  fail "it links to an AI coding session or tool. Remove the link."
fi

[ -n "$subject" ] || fail "the message is empty."

# Merge and revert subjects created by git itself are allowed.
merge_re='^(Merge |Revert ")'
if [[ "$subject" =~ $merge_re ]]; then
  exit 0
fi

cc_re='^(feat|fix|test|docs|refactor|perf|build|ci|chore)(\([a-z0-9._/-]+\))?!?: [^ ]'
if ! [[ "$subject" =~ $cc_re ]]; then
  fail "the subject \"${subject}\" is not a Conventional Commit, for example \"feat(core): add intent hashing\"."
fi
if [ "${#subject}" -gt 100 ]; then
  fail "the subject is longer than 100 characters."
fi
