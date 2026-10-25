"""Helpers for tests that drive the bash scripts and throwaway git repos."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
OWNER_NAME = "nagendhra-web"
OWNER_EMAIL = "nagendhra405@gmail.com"


def find_bash() -> str | None:
    """Bash for the scripts. On Windows prefer Git for Windows bash over WSL bash."""
    if sys.platform == "win32":
        git = shutil.which("git")
        if git:
            base = Path(git).resolve().parent.parent
            for candidate in (base / "usr" / "bin" / "bash.exe", base / "bin" / "bash.exe"):
                if candidate.is_file():
                    return str(candidate)
    return shutil.which("bash")


BASH = find_bash()


def run_bash(
    args: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``bash <args>`` and capture output. Missing bash fails the test."""
    assert BASH is not None, "bash is required for the guard scripts"
    return subprocess.run(
        [BASH, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        env={**clean_env(), **(env or {})},
        input=stdin if stdin is not None else "",
    )


def run_script(
    name: str,
    *args: str,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one of the scripts in scripts/."""
    return run_bash([str(SCRIPTS / name), *args], cwd=cwd, env=env, stdin=stdin)


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    """Run git in ``repo`` and return stdout."""
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env={**clean_env(), **(env or {})},
    ).stdout.strip()


def make_repo(path: Path, name: str = OWNER_NAME, email: str = OWNER_EMAIL) -> Path:
    """Create a git repo with the given identity and one commit."""
    path.mkdir(parents=True)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.name", name)
    git(path, "config", "user.email", email)
    git(path, "config", "commit.gpgsign", "false")
    (path / "README.md").write_text("demo\n", encoding="utf-8")
    git(path, "add", "README.md")
    git(path, "commit", "-q", "-m", "docs: first commit")
    return path


def clean_env() -> dict[str, str]:
    """The calling environment minus anything that would leak into a guard test.

    Tests also run inside git hooks (the pre-push hook runs `make ci`), where
    ARBITR_PUSH_APPROVED, PRE_COMMIT_* and GIT_* (including GIT_DIR, which
    would point git at the real repo) are set. Every subprocess starts from
    this, and a test adds back only what it means to set.
    """
    return {
        k: v
        for k, v in os.environ.items()
        if k.upper() != "ARBITR_PUSH_APPROVED" and not k.upper().startswith(("PRE_COMMIT", "GIT_"))
    }
