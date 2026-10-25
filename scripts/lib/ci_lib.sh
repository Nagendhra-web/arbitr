#!/usr/bin/env bash
# Stage bookkeeping for scripts/ci.sh. Source this file, do not run it.
# Kept separate so tests/repo/test_ci_script.py can test it directly.
#
# Rules:
# - A stage that returns nonzero is FAIL. No exit code means PENDING.
# - A stage is PENDING only when it calls `pending <id>` and <id> is listed in
#   the pending file. Calling `pending` for an unlisted id is a FAIL.
# - A suite listed as pending that already has tests is a FAIL, so a stale
#   entry can never hide real tests.

CI_PENDING_FILE="${CI_PENDING_FILE:-scripts/ci-pending.txt}"

STAGE_NAMES=()
STAGE_RESULTS=()
STAGE_SECONDS=()
STAGE_NOTES=()
NOTE=""
STAGE_PENDING=0

is_pending() {
  # is_pending <id>: true when <id> is listed in the pending file.
  local id line
  id="$1"
  [ -f "$CI_PENDING_FILE" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    [ "${line%%[[:space:]]*}" = "$id" ] && return 0
  done < "$CI_PENDING_FILE"
  return 1
}

pending_reason() {
  # pending_reason <id>: the reason text for a listed id.
  local id line rest
  id="$1"
  while IFS= read -r line || [ -n "$line" ]; do
    [ "${line%%[[:space:]]*}" = "$id" ] || continue
    rest="${line#"$id"}"
    rest="${rest#"${rest%%[![:space:]]*}"}"
    printf '%s' "$rest"
    return 0
  done < "$CI_PENDING_FILE"
}

add_note() {
  NOTE="${NOTE:+$NOTE; }$1"
}

pending() {
  # pending <id>: mark the current stage PENDING if <id> is listed, else fail.
  if is_pending "$1"; then
    STAGE_PENDING=1
    add_note "$1 pending: $(pending_reason "$1")"
    return 0
  fi
  echo "FAIL: '$1' has nothing to run and is not listed in $CI_PENDING_FILE." >&2
  return 1
}

pending_unless_exists() {
  # pending_unless_exists <id> <entry point>: 0 means "run the stage now",
  # 2 means "stage is pending", anything else is a failure.
  local id="$1" entry="$2"
  if [ -e "$entry" ]; then
    if is_pending "$id"; then
      echo "FAIL: $entry exists but '$id' is still listed in $CI_PENDING_FILE. Remove the entry." >&2
      return 1
    fi
    return 0
  fi
  pending "$id" || return 1
  return 2
}

has_tests() {
  # has_tests <dir>: true when the directory holds at least one test module.
  local f
  [ -d "$1" ] || return 1
  while IFS= read -r f; do
    [ -n "$f" ] && return 0
  done < <(find "$1" -name 'test_*.py' -print 2>/dev/null)
  return 1
}

suites_ready() {
  # suites_ready <id:dir>...: sets READY_DIRS to the dirs that have tests.
  # A suite without tests must be pending. A pending suite must not have tests.
  local spec id dir
  READY_DIRS=()
  for spec in "$@"; do
    id="${spec%%:*}"
    dir="${spec#*:}"
    if has_tests "$dir"; then
      if is_pending "$id"; then
        echo "FAIL: $dir has tests but '$id' is still listed in $CI_PENDING_FILE. Remove the entry." >&2
        return 1
      fi
      READY_DIRS+=("$dir")
    else
      if ! is_pending "$id"; then
        echo "FAIL: $dir has no tests and '$id' is not listed in $CI_PENDING_FILE." >&2
        return 1
      fi
      add_note "$id pending: $(pending_reason "$id")"
    fi
  done
  # Every suite pending (and listed): the whole stage is PENDING.
  [ "${#READY_DIRS[@]}" -gt 0 ] || STAGE_PENDING=1
}

record_path() {
  # record_path <sha> <mode fast|full> <in_container true|false> <tree_clean true|false>
  # Full host runs, full container runs and fast runs never share a file, and
  # a dirty-tree run can never overwrite a clean-tree record.
  local sha="$1" mode="$2" in_container="$3" clean="$4" kind
  if [ "$mode" = "fast" ]; then
    kind="fast"
  elif [ "$in_container" = "true" ]; then
    kind="docker"
  else
    kind="host"
  fi
  [ "$clean" = "true" ] || kind="${kind}-dirty"
  printf 'ci-logs/%s.%s.json' "$sha" "$kind"
}

run_stage() {
  # run_stage <name> <function>: run one stage and record its result.
  # Calls `finish 1` on FAIL; scripts/ci.sh defines finish.
  local name="$1" fn="$2" start end rc result
  NOTE=""
  STAGE_PENDING=0
  echo
  echo "================================================================"
  echo "== ${name}"
  echo "================================================================"
  start="$(date +%s)"
  "$fn"
  rc=$?
  end="$(date +%s)"
  if [ "$rc" -ne 0 ]; then
    result="FAIL"
  elif [ "$STAGE_PENDING" -eq 1 ]; then
    result="PENDING"
  else
    result="PASS"
  fi
  STAGE_NAMES+=("$name")
  STAGE_RESULTS+=("$result")
  STAGE_SECONDS+=("$((end - start))")
  STAGE_NOTES+=("$NOTE")
  if [ "$result" = "FAIL" ]; then
    finish 1
  fi
}
