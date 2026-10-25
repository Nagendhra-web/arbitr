"""Under ARBITR_CI=1 any skip fails the session (tests/conftest.py).

Each case runs a sample test module in a fresh pytest process with a copy of
tests/conftest.py, both serially and under xdist, because CI runs with -n auto.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

CONFTEST = Path(__file__).resolve().parents[1] / "conftest.py"

SKIP_IN_TEST = """
import pytest

def test_ok() -> None:
    pass

def test_skipped() -> None:
    pytest.skip("not here")
"""

SKIP_MODULE_LEVEL = """
import pytest

pytest.skip("whole module", allow_module_level=True)

def test_never_runs() -> None:
    pass
"""

IMPORTORSKIP_MODULE_LEVEL = """
import pytest

missing = pytest.importorskip("arbitr_no_such_module_for_this_test")

def test_never_runs() -> None:
    pass
"""

SKIPIF_MARK = """
import pytest

@pytest.mark.skipif(True, reason="marked")
def test_marked() -> None:
    pass
"""

XFAIL_ONLY = """
import pytest

def test_ok() -> None:
    pass

@pytest.mark.xfail(strict=True)
def test_expected_failure() -> None:
    raise AssertionError
"""

SKIPPING_BODIES = {
    "skip-in-test": SKIP_IN_TEST,
    "module-level-skip": SKIP_MODULE_LEVEL,
    "module-level-importorskip": IMPORTORSKIP_MODULE_LEVEL,
    "skipif-mark": SKIPIF_MARK,
}
MODES = {"serial": ["-p", "no:xdist"], "xdist": ["-n", "2"]}


def run_sample(tmp_path: Path, body: str, mode: list[str], *, ci: bool) -> tuple[int, str]:
    shutil.copy(CONFTEST, tmp_path / "conftest.py")
    (tmp_path / "test_ok_module.py").write_text("def test_fine() -> None:\n    pass\n")
    (tmp_path / "test_sample.py").write_text(body, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "ARBITR_CI"}
    if ci:
        env["ARBITR_CI"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *mode, "."],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return result.returncode, result.stdout + result.stderr


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("case", sorted(SKIPPING_BODIES))
def test_skip_fails_under_ci(tmp_path: Path, case: str, mode: str) -> None:
    rc, out = run_sample(tmp_path, SKIPPING_BODIES[case], MODES[mode], ci=True)
    assert rc == pytest.ExitCode.TESTS_FAILED, out
    assert "while ARBITR_CI=1" in out
    assert "test_sample.py" in out


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("case", sorted(SKIPPING_BODIES))
def test_skip_allowed_outside_ci(tmp_path: Path, case: str, mode: str) -> None:
    rc, out = run_sample(tmp_path, SKIPPING_BODIES[case], MODES[mode], ci=False)
    assert rc == 0, out


@pytest.mark.parametrize("mode", sorted(MODES))
def test_xfail_is_not_a_skip(tmp_path: Path, mode: str) -> None:
    rc, out = run_sample(tmp_path, XFAIL_ONLY, MODES[mode], ci=True)
    assert rc == 0, out
