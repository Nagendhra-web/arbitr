#!/usr/bin/env bash
# The full local CI pipeline.
#
#   scripts/ci.sh           full pipeline, called by `make ci`
#   scripts/ci.sh --fast    stages 1 to 4 plus unit tests, called by `make ci-fast`
#
# Stages run in order and the run stops at the first failure. A summary table
# with each stage's duration is printed at the end. The full log goes to
# ci-logs/<UTC timestamp>-<short sha>.log and a machine-readable record to
# ci-logs/<sha>.<host|docker|fast>[-dirty].json.
#
# Stage results are PASS, FAIL or PENDING. A stage is PENDING only when the
# feature it tests is listed in scripts/ci-pending.txt. Any nonzero exit is a
# FAIL, and a skip never looks like a pass (scripts/lib/ci_lib.sh).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=lib/env.sh
. scripts/lib/env.sh
# shellcheck source=lib/ci_lib.sh
. scripts/lib/ci_lib.sh

MODE="full"
[ "${1:-}" = "--fast" ] && MODE="fast"

# Tests fail the session on any skip while this is set (tests/conftest.py).
export ARBITR_CI=1

SIM_SEEDS="${ARBITR_SIM_SEEDS:-2000}"
TLC_MODEL="${ARBITR_TLC_MODEL:-small}"

if SHA_FULL="$(git rev-parse --verify -q HEAD 2>/dev/null)"; then HAS_COMMITS=1; else
  SHA_FULL="0000000000000000000000000000000000000000"
  HAS_COMMITS=0
fi
SHA="${SHA_FULL:0:12}"
if [ -z "$(git status --porcelain 2>/dev/null)" ]; then TREE_CLEAN=true; else TREE_CLEAN=false; fi
if [ -f /.dockerenv ]; then IN_CONTAINER=true; else IN_CONTAINER=false; fi
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p ci-logs
LOG="ci-logs/$(date -u +%Y%m%dT%H%M%SZ)-${SHA}.log"
RECORD="$(record_path "$SHA_FULL" "$MODE" "$IN_CONTAINER" "$TREE_CLEAN")"
exec > >(tee -a "$LOG") 2>&1

PG_STARTED=0

cleanup() {
  if [ "$PG_STARTED" -eq 1 ]; then
    echo "Stopping test Postgres."
    compose -f deploy/docker-compose.yml down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ------------------------------------------------------------------ helpers

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL: docker is not installed or not on PATH. This stage needs Docker. Start Docker and rerun." >&2
    return 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "FAIL: Docker is installed but the daemon is not running. Start Docker Desktop and rerun." >&2
    return 1
  fi
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "FAIL: '$1' is not installed or not on PATH. $2" >&2
    return 1
  fi
}

start_postgres() {
  [ "$PG_STARTED" -eq 1 ] && return 0
  require_docker || return 1
  echo "Starting test Postgres on ${ARBITR_PG_HOST}:${ARBITR_PG_PORT}."
  compose -f deploy/docker-compose.yml up -d --wait postgres || return 1
  PG_STARTED=1
}

pytest_run() {
  uv run --locked pytest -p no:cacheprovider "$@"
}

stages_tsv() {
  local i
  for ((i = 0; i < ${#STAGE_NAMES[@]}; i++)); do
    printf '%s\t%s\t%s\t%s\n' "${STAGE_NAMES[$i]}" "${STAGE_RESULTS[$i]}" \
      "${STAGE_SECONDS[$i]}" "${STAGE_NOTES[$i]}"
  done
}

write_record() {
  uv run --no-sync python scripts/write_ci_record.py "$RECORD" \
    --sha "$SHA_FULL" --mode "$MODE" --result "$1" \
    --tree-clean "$TREE_CLEAN" --in-container "$IN_CONTAINER" \
    --started "$STARTED" --log "$LOG" \
    --image-digest "${ARBITR_CI_IMAGE_DIGEST:-}" \
    --stages "$(stages_tsv)"
}

finish() {
  local rc="$1" overall i
  [ "$rc" -eq 0 ] && overall="pass" || overall="fail"
  echo
  echo "================================================================"
  printf '%-4s %-34s %-8s %6s  %s\n' "#" "Stage" "Result" "Time" "Note"
  printf '%-4s %-34s %-8s %6s  %s\n' "--" "-----" "------" "----" "----"
  for ((i = 0; i < ${#STAGE_NAMES[@]}; i++)); do
    printf '%-4s %-34s %-8s %5ss  %s\n' "$((i + 1))" "${STAGE_NAMES[$i]}" \
      "${STAGE_RESULTS[$i]}" "${STAGE_SECONDS[$i]}" "${STAGE_NOTES[$i]}"
  done
  echo "================================================================"
  # A file changed during the run means the run did not test exactly this commit.
  if [ "$TREE_CLEAN" = "true" ] && [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "The working tree changed during the run, so it is recorded as dirty:"
    git status --porcelain | head -10
    TREE_CLEAN=false
    RECORD="$(record_path "$SHA_FULL" "$MODE" "$IN_CONTAINER" "$TREE_CLEAN")"
  fi
  echo "CI ${MODE} result: ${overall^^} at ${SHA} (tree clean: ${TREE_CLEAN}, container: ${IN_CONTAINER})"
  echo "Log: $LOG"
  if write_record "$overall"; then
    echo "Record: $RECORD"
  else
    echo "FAIL: could not write the CI record $RECORD" >&2
    rc=1
  fi
  exit "$rc"
}

# ------------------------------------------------------------------ stages

s_deps() { uv sync --locked --all-extras; }

s_lint() { uv run --locked ruff check . && uv run --locked ruff format --check .; }

s_types() { uv run --locked mypy --strict; }

s_writing() { bash scripts/check_no_em_dash.sh; }

s_git_rules() {
  if [ "$HAS_COMMITS" -eq 0 ]; then
    STAGE_PENDING=1
    add_note "no commits yet, nothing to check"
    return 0
  fi
  bash scripts/check_commits.sh
}

s_security() {
  require_tool gitleaks "Install it (winget install Gitleaks.Gitleaks, brew install gitleaks)." || return 1
  require_tool osv-scanner "Install it (winget install Google.OSVScanner, brew install osv-scanner)." || return 1
  local req rc
  req="$(mktemp)"
  echo "-- bandit" && uv run --locked bandit -q -c pyproject.toml -r src -ll || return 1
  echo "-- pip-audit"
  uv export --locked --all-extras --no-emit-project --format requirements-txt -o "$req" >/dev/null || return 1
  uv run --locked pip-audit --strict --disable-pip --progress-spinner off -r "$req"
  rc=$?
  rm -f "$req"
  [ "$rc" -eq 0 ] || return 1
  echo "-- gitleaks (working tree)" && gitleaks dir . --redact --no-banner --config .gitleaks.toml || return 1
  if [ "$HAS_COMMITS" -eq 1 ]; then
    echo "-- gitleaks (history)" && gitleaks git . --redact --no-banner --config .gitleaks.toml || return 1
  fi
  echo "-- osv-scanner" && osv-scanner scan source --lockfile uv.lock
}

s_unit() {
  suites_ready unit:tests/unit property:tests/property repo:tests/repo || return 1
  local cov=(--cov=arbitr --cov-report=term --cov-report=json:ci-logs/coverage.json --cov-fail-under=90)
  [ "$MODE" = "fast" ] && cov=()
  pytest_run "${READY_DIRS[@]}" src/arbitr --doctest-modules -n auto "${cov[@]}" || return 1
  if [ "$MODE" = "full" ]; then
    uv run --locked python scripts/check_coverage.py ci-logs/coverage.json || return 1
  fi
}

s_simulation() {
  suites_ready simulation:tests/simulation || return 1
  pytest_run tests/simulation -q || return 1
  uv run --locked python tests/simulation/run.py --seeds "$SIM_SEEDS"
}

s_formal() {
  require_tool java "Install a Java 11+ runtime (winget install EclipseAdoptium.Temurin.21.JRE)." || return 1
  bash scripts/tlc.sh "$TLC_MODEL"
}

s_matrix() {
  uv run --locked nox -s tests-3.11 tests-3.12 tests-3.13
}

s_postgres() {
  start_postgres || return 1
  ARBITR_TEST_BACKEND=postgres pytest_run tests -m backend -q
}

s_fault_concurrency() {
  suites_ready fault:tests/fault concurrency:tests/concurrency || return 1
  [ "$STAGE_PENDING" -eq 1 ] && return 0
  start_postgres || return 1
  echo "-- backend: sqlite" && ARBITR_TEST_BACKEND=sqlite pytest_run "${READY_DIRS[@]}" -q || return 1
  # Executor suites marked sqlite_only cannot run on Postgres until the executor
  # stores its ledger there; they show as a listed pending item, never a skip.
  local marked=0
  grep -rlq --include='*.py' "mark.sqlite_only" tests && marked=1
  if [ "$marked" -eq 1 ] && ! is_pending executor-postgres; then
    echo "FAIL: tests marked sqlite_only need 'executor-postgres' in $CI_PENDING_FILE." >&2
    return 1
  fi
  if [ "$marked" -eq 0 ] && is_pending executor-postgres; then
    echo "FAIL: no test is marked sqlite_only; remove 'executor-postgres' from $CI_PENDING_FILE." >&2
    return 1
  fi
  add_note "executor-postgres pending: $(pending_reason executor-postgres)"
  echo "-- backend: postgres" && ARBITR_TEST_BACKEND=postgres pytest_run "${READY_DIRS[@]}" -q -m "not sqlite_only"
}

s_integrations() {
  suites_ready integration:tests/integration mcp:tests/mcp || return 1
  [ "$STAGE_PENDING" -eq 1 ] && return 0
  # In the full pipeline, coverage is appended to the unit stage's data, so the
  # adapters' floors are checked against both suites together.
  local cov=()
  [ "$MODE" = "full" ] && cov=(--cov=arbitr --cov-append --cov-report=json:ci-logs/coverage.json)
  pytest_run "${READY_DIRS[@]}" -q "${cov[@]}" || return 1
  if [ "$MODE" = "full" ]; then
    uv run --locked python scripts/check_coverage.py ci-logs/coverage.json --with-integrations || return 1
  fi
}

# For stages with one entry point: run it if it exists, else the stage must be pending.
gated() {
  local rc
  pending_unless_exists "$1" "$2"
  rc=$?
  [ "$rc" -eq 2 ] && return 0
  [ "$rc" -eq 0 ] || return 1
  shift 2
  "$@"
}

s_bench() { gated bench bench/scenarios/__init__.py uv run --locked arbitr bench --assert; }

s_perf() {
  gated perf bench/perf.py \
    uv run --locked python bench/perf.py --quick --compare bench/perf_baseline.json
}

s_package() {
  local venv py
  rm -rf dist .tools/pkg-venv
  uv build || return 1
  uv run --locked twine check --strict dist/* || return 1
  venv=".tools/pkg-venv"
  uv venv -q --python 3.11 "$venv" || return 1
  if [ -x "$venv/Scripts/python.exe" ]; then py="$venv/Scripts/python.exe"; else py="$venv/bin/python"; fi
  uv pip install -q --python "$py" dist/*.whl || return 1
  (cd "$(mktemp -d)" && "$ROOT/$py" "$ROOT/scripts/smoke_quickstart.py")
}

s_docs() { uv run --locked mkdocs build --strict --site-dir .tools/site; }

ts_client() { (cd clients/typescript && npm ci && npm test && npm run build); }
s_typescript() { gated typescript clients/typescript/package.json ts_client; }

# ------------------------------------------------------------------ pipeline

echo "Arbitr local CI (${MODE}) at ${SHA}, tree clean: ${TREE_CLEAN}, container: ${IN_CONTAINER}, $(uname -srm)"

run_stage "Dependencies (uv sync --locked)" s_deps
run_stage "Lint and format (ruff)" s_lint
run_stage "Types (mypy --strict)" s_types
run_stage "Writing rule (no em dashes)" s_writing
if [ "$MODE" = "fast" ]; then
  run_stage "Unit, property, repo, doc tests" s_unit
  finish 0
fi
run_stage "Git rules (authorship, messages)" s_git_rules
run_stage "Security scans" s_security
run_stage "Unit, property, repo, doc tests" s_unit
run_stage "Deterministic simulation" s_simulation
run_stage "TLA+ model check (TLC ${TLC_MODEL})" s_formal
run_stage "Python matrix (3.11 3.12 3.13)" s_matrix
run_stage "Postgres backend tests" s_postgres
run_stage "Fault injection and concurrency" s_fault_concurrency
run_stage "Integrations and MCP" s_integrations
run_stage "Scripted bench" s_bench
run_stage "Perf smoke" s_perf
run_stage "Package build and smoke" s_package
run_stage "Docs (mkdocs --strict)" s_docs
run_stage "TypeScript client" s_typescript
finish 0
