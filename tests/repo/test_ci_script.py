"""Tests for the CI stage logic in scripts/lib/ci_lib.sh.

Each test runs a tiny pipeline in bash that sources ci_lib.sh with its own
pending file, then reads back the recorded stage results.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from shellutil import SCRIPTS, run_bash

if TYPE_CHECKING:
    from pathlib import Path

HARNESS = r"""
set -uo pipefail
CI_PENDING_FILE="$1"
cd "$2"
. "$3"
finish() {
  local i
  for ((i = 0; i < ${#STAGE_NAMES[@]}; i++)); do
    printf '%s=%s|%s\n' "${STAGE_NAMES[$i]}" "${STAGE_RESULTS[$i]}" "${STAGE_NOTES[$i]}"
  done
  exit "$1"
}
"""

PENDING = "# comment line\nbench bench later\nfault    fault harness later\n"


def pipeline(tmp_path: Path, body: str, pending: str = PENDING) -> tuple[int, dict[str, str]]:
    pf = tmp_path / "pending.txt"
    pf.write_text(pending, encoding="utf-8")
    script = HARNESS + body + "\nfinish 0\n"
    lib = str(SCRIPTS / "lib" / "ci_lib.sh")
    result = run_bash(["-c", script, "_", str(pf), str(tmp_path), lib])
    stages = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            name, rest = line.split("=", 1)
            stages[name] = rest
    return result.returncode, stages


def result_of(stages: dict[str, str], name: str) -> str:
    return stages[name].split("|", 1)[0]


def test_pass_stage(tmp_path: Path) -> None:
    rc, stages = pipeline(tmp_path, "ok() { return 0; }\nrun_stage s ok")
    assert rc == 0
    assert result_of(stages, "s") == "PASS"


@pytest.mark.parametrize("code", [1, 2, 3, 4, 5, 127])
def test_any_nonzero_exit_is_fail(tmp_path: Path, code: int) -> None:
    """pytest exits 3 on an internal error. No exit code may mean PENDING."""
    rc, stages = pipeline(tmp_path, f"bad() {{ return {code}; }}\nrun_stage s bad")
    assert rc == 1
    assert result_of(stages, "s") == "FAIL"


def test_fail_stops_the_pipeline(tmp_path: Path) -> None:
    body = "bad() { return 1; }\nok() { return 0; }\nrun_stage a bad\nrun_stage b ok"
    rc, stages = pipeline(tmp_path, body)
    assert rc == 1
    assert "b" not in stages


def test_listed_pending_is_pending(tmp_path: Path) -> None:
    rc, stages = pipeline(tmp_path, "p() { pending bench; }\nrun_stage s p")
    assert rc == 0
    assert result_of(stages, "s") == "PENDING"
    assert "bench later" in stages["s"]


def test_unlisted_pending_is_fail(tmp_path: Path) -> None:
    rc, stages = pipeline(tmp_path, "p() { pending perf; }\nrun_stage s p")
    assert rc == 1
    assert result_of(stages, "s") == "FAIL"


def test_pending_id_must_match_exactly(tmp_path: Path) -> None:
    """'ben' is not 'bench', and a commented line lists nothing."""
    rc, _ = pipeline(tmp_path, "p() { pending ben; }\nrun_stage s p")
    assert rc == 1
    rc, _ = pipeline(tmp_path, "p() { pending comment; }\nrun_stage s p")
    assert rc == 1


def make_suite(tmp_path: Path, name: str, *, with_test: bool) -> None:
    d = tmp_path / name
    d.mkdir()
    if with_test:
        (d / "test_x.py").write_text("def test_x() -> None:\n    pass\n", encoding="utf-8")


def test_unlisted_empty_suite_fails(tmp_path: Path) -> None:
    make_suite(tmp_path, "unit", with_test=False)
    rc, stages = pipeline(tmp_path, "s() { suites_ready unit:unit; }\nrun_stage s s")
    assert rc == 1
    assert result_of(stages, "s") == "FAIL"


def test_listed_empty_suite_is_pending(tmp_path: Path) -> None:
    make_suite(tmp_path, "fault", with_test=False)
    body = (
        "s() { suites_ready fault:fault || return 1;"
        ' [ "$STAGE_PENDING" -eq 1 ] && return 0; return 9; }'
    )
    rc, stages = pipeline(tmp_path, body + "\nrun_stage s s")
    assert rc == 0
    assert result_of(stages, "s") == "PENDING"


def test_listed_suite_with_tests_fails(tmp_path: Path) -> None:
    """A stale pending entry must never hide real tests."""
    make_suite(tmp_path, "fault", with_test=True)
    rc, stages = pipeline(tmp_path, "s() { suites_ready fault:fault; }\nrun_stage s s")
    assert rc == 1
    assert result_of(stages, "s") == "FAIL"


def test_mixed_suites_run_ready_dirs(tmp_path: Path) -> None:
    make_suite(tmp_path, "fault", with_test=False)
    make_suite(tmp_path, "concurrency", with_test=True)
    body = (
        "s() { suites_ready fault:fault concurrency:concurrency || return 1;"
        ' [ "${READY_DIRS[*]}" = "concurrency" ]; }'
    )
    rc, stages = pipeline(tmp_path, body + "\nrun_stage s s")
    assert rc == 0
    assert result_of(stages, "s") == "PASS"
    assert "fault pending" in stages["s"]


@pytest.mark.parametrize(
    ("exists", "listed", "expected"),
    [
        (True, True, "FAIL"),  # entry point exists but still listed: stale entry
        (True, False, "PASS"),  # entry point exists: the stage runs
        (False, True, "PENDING"),
        (False, False, "FAIL"),  # nothing to run and not listed
    ],
)
def test_pending_unless_exists(tmp_path: Path, exists: bool, listed: bool, expected: str) -> None:
    if exists:
        (tmp_path / "entry.py").write_text("", encoding="utf-8")
    pending = "bench later\n" if listed else ""
    body = (
        "g() { local rc; pending_unless_exists bench entry.py; rc=$?;"
        " [ $rc -eq 2 ] && return 0; [ $rc -eq 0 ] || return 1; return 0; }"
    )
    _, stages = pipeline(tmp_path, body + "\nrun_stage s g", pending=pending)
    assert result_of(stages, "s") == expected


def record(tmp_path: Path, *args: str) -> str:
    rc, _ = pipeline(tmp_path, "")
    assert rc == 0
    lib = str(SCRIPTS / "lib" / "ci_lib.sh")
    out = run_bash(["-c", '. "$1"; shift; record_path "$@"', "_", lib, *args])
    return out.stdout.strip()


def test_record_paths_never_collide(tmp_path: Path) -> None:
    paths = {
        record(tmp_path, "abc", mode, container, clean)
        for mode in ("fast", "full")
        for container in ("true", "false")
        for clean in ("true", "false")
    }
    # Six distinct files: fast, host and docker, each clean or dirty.
    assert paths == {
        "ci-logs/abc.fast.json",
        "ci-logs/abc.fast-dirty.json",
        "ci-logs/abc.host.json",
        "ci-logs/abc.host-dirty.json",
        "ci-logs/abc.docker.json",
        "ci-logs/abc.docker-dirty.json",
    }


def test_fast_run_never_writes_a_full_record(tmp_path: Path) -> None:
    for container in ("true", "false"):
        for clean in ("true", "false"):
            path = record(tmp_path, "abc", "fast", container, clean)
            assert ".host" not in path
            assert ".docker" not in path


def test_ci_sh_uses_the_tested_library() -> None:
    text = (SCRIPTS / "ci.sh").read_text(encoding="utf-8")
    assert ". scripts/lib/ci_lib.sh" in text
    assert "export ARBITR_CI=1" in text
    # The only way to PENDING is the library's pending helpers.
    assert "return 3" not in text


def test_ci_sh_rechecks_the_tree_at_finish() -> None:
    """A file edited during a run must turn the record dirty."""
    text = (SCRIPTS / "ci.sh").read_text(encoding="utf-8")
    finish = text[text.index("finish() {") :]
    assert "git status --porcelain" in finish
    assert "TREE_CLEAN=false" in finish
    assert 'RECORD="$(record_path' in finish
