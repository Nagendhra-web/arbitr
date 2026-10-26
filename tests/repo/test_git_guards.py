"""Tests for the git guard scripts."""

from __future__ import annotations

from pathlib import Path

import pytest

from shellutil import (
    BASH,
    OWNER_EMAIL,
    OWNER_NAME,
    SCRIPTS,
    clean_env,
    git,
    make_repo,
    run_bash,
    run_script,
)


def test_bash_is_available() -> None:
    assert BASH is not None, "bash is required for the guard scripts"


# ---------------------------------------------------------------- commit messages


def check_msg(tmp_path: Path, message: str) -> tuple[int, str]:
    f = tmp_path / "COMMIT_EDITMSG"
    f.write_text(message, encoding="utf-8")
    result = run_script("check_commit_msg.sh", str(f))
    return result.returncode, result.stderr


@pytest.mark.parametrize(
    "message",
    [
        "feat(core): add intent hashing",
        "fix: handle an empty policy file",
        "build!: drop Python 3.10",
        "docs: explain recovery\n\nLonger body in plain English.",
        "Merge branch 'main' into feature",
        'Revert "feat: add x"',
    ],
)
def test_commit_msg_accepts(tmp_path: Path, message: str) -> None:
    rc, err = check_msg(tmp_path, message)
    assert rc == 0, err


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        ("feat: x\n\nCo-" + "Authored-By: Bot <bot@example.com>", "Co-Authored-By"),
        ("feat: x\n\nco-" + "authored-by: bot", "Co-Authored-By"),
        ("feat: x\n\n" + "Generated" + " with a tool", "Generated with"),
        ("feat: x\n\nsee noreply@" + "anthropic.com", "noreply"),
        ("feat: x\n\nhttps://claude.ai/" + "code/session_123", "session"),
        ("added stuff", "Conventional Commit"),
        ("Feat: capitalised type", "Conventional Commit"),
        ("feat:missing space", "Conventional Commit"),
        ("style: not an allowed type", "Conventional Commit"),
        ("revert: not an allowed type", "Conventional Commit"),
        ("feat: " + "x" * 120, "longer than 100"),
        ("# only a comment\n", "empty"),
    ],
)
def test_commit_msg_rejects(tmp_path: Path, message: str, reason: str) -> None:
    rc, err = check_msg(tmp_path, message)
    assert rc == 1
    assert reason in err


def test_commit_msg_ignores_git_comment_lines(tmp_path: Path) -> None:
    message = "fix: real subject\n# Co-" + "Authored-By: in a comment git strips anyway\n"
    assert check_msg(tmp_path, message)[0] == 0


def test_commit_msg_handles_crlf(tmp_path: Path) -> None:
    rc, err = check_msg(tmp_path, "fix: windows line endings\r\n\r\nbody\r\n")
    assert rc == 0, err


# ---------------------------------------------------------------- author guard


def test_author_check_accepts_owner(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    result = run_script("check_author.sh", cwd=repo, env=clean_env())
    assert result.returncode == 0, result.stderr


def test_author_check_rejects_another_name(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r", name="someone-else")
    result = run_script("check_author.sh", cwd=repo, env=clean_env())
    assert result.returncode == 1
    assert "name" in result.stderr


def test_author_check_rejects_another_email(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r", email="other@example.com")
    result = run_script("check_author.sh", cwd=repo, env=clean_env())
    assert result.returncode == 1
    assert "email" in result.stderr


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("GIT_AUTHOR_EMAIL", "other@example.com"),
        ("GIT_COMMITTER_EMAIL", "other@example.com"),
        ("GIT_AUTHOR_NAME", "someone-else"),
        ("GIT_COMMITTER_NAME", "someone-else"),
    ],
)
def test_author_check_sees_env_overrides(tmp_path: Path, var: str, value: str) -> None:
    repo = make_repo(tmp_path / "r")
    result = run_script("check_author.sh", cwd=repo, env={**clean_env(), var: value})
    assert result.returncode == 1, f"{var} override was not caught"


# ---------------------------------------------------------------- commit history check


def test_check_commits_passes_owner_history(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    result = run_script("check_commits.sh", cwd=repo, env=clean_env())
    assert result.returncode == 0, result.stderr


def test_check_commits_rejects_foreign_email(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    (repo / "x.txt").write_text("x\n", encoding="utf-8")
    git(repo, "add", "x.txt")
    git(repo, "commit", "-q", "-m", "fix: x", env={"GIT_AUTHOR_EMAIL": "other@example.com"})
    result = run_script("check_commits.sh", cwd=repo, env=clean_env())
    assert result.returncode == 1
    assert "email" in result.stderr


def test_check_commits_rejects_bad_message(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    git(repo, "commit", "-q", "--allow-empty", "-m", "fix: x", "-m", "Co-" + "Authored-By: b <b@x>")
    result = run_script("check_commits.sh", cwd=repo, env=clean_env())
    assert result.returncode == 1


def test_check_commits_with_no_commits(tmp_path: Path) -> None:
    repo = tmp_path / "empty"
    repo.mkdir()
    git(repo, "init", "-q")
    result = run_script("check_commits.sh", cwd=repo, env=clean_env())
    assert result.returncode == 0
    assert "No commits yet" in result.stdout


# ---------------------------------------------------------------- push guard


def test_pre_push_guard_blocks_without_approval() -> None:
    result = run_script("pre_push_guard.sh", env=clean_env())
    assert result.returncode == 1
    assert "push blocked" in result.stderr


@pytest.mark.parametrize("value", ["0", "yes", "true", ""])
def test_pre_push_guard_needs_exactly_one(value: str) -> None:
    result = run_script("pre_push_guard.sh", env={**clean_env(), "ARBITR_PUSH_APPROVED": value})
    assert result.returncode == 1


def _approved(**extra: str) -> dict[str, str]:
    return {**clean_env(), "ARBITR_PUSH_APPROVED": "1", **extra}


def test_pre_push_guard_allows_clean_head(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    head = git(repo, "rev-parse", "HEAD")
    result = run_script("pre_push_guard.sh", cwd=repo, env=_approved(PRE_COMMIT_TO_REF=head))
    assert result.returncode == 0, result.stderr


def test_pre_push_guard_reads_refs_from_stdin(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    head = git(repo, "rev-parse", "HEAD")
    line = f"refs/heads/main {head} refs/heads/main {'0' * 40}\n"
    result = run_script("pre_push_guard.sh", cwd=repo, env=_approved(), stdin=line)
    assert result.returncode == 0, result.stderr


def test_pre_push_guard_first_push_uses_local_branch(tmp_path: Path) -> None:
    """First push to an empty remote: pre-commit sets only PRE_COMMIT_LOCAL_BRANCH."""
    repo = make_repo(tmp_path / "r")
    env = _approved(PRE_COMMIT_LOCAL_BRANCH="refs/heads/main")
    result = run_script("pre_push_guard.sh", cwd=repo, env=env)
    assert result.returncode == 0, result.stderr


def test_pre_push_guard_blocks_other_local_branch(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    git(repo, "branch", "old")
    git(repo, "commit", "-q", "--allow-empty", "-m", "fix: newer")
    env = _approved(PRE_COMMIT_LOCAL_BRANCH="refs/heads/old")
    result = run_script("pre_push_guard.sh", cwd=repo, env=env)
    assert result.returncode == 1
    assert "HEAD is" in result.stderr


def test_pre_push_guard_blocks_untracked_file(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    head = git(repo, "rev-parse", "HEAD")
    (repo / "stray.py").write_text("x = 1\n", encoding="utf-8")
    result = run_script("pre_push_guard.sh", cwd=repo, env=_approved(PRE_COMMIT_TO_REF=head))
    assert result.returncode == 1
    assert "uncommitted or untracked" in result.stderr


def test_pre_push_guard_blocks_modified_file(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    head = git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    result = run_script("pre_push_guard.sh", cwd=repo, env=_approved(PRE_COMMIT_TO_REF=head))
    assert result.returncode == 1


def test_pre_push_guard_blocks_pushing_another_commit(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    first = git(repo, "rev-parse", "HEAD")
    git(repo, "commit", "-q", "--allow-empty", "-m", "fix: second")
    result = run_script("pre_push_guard.sh", cwd=repo, env=_approved(PRE_COMMIT_TO_REF=first))
    assert result.returncode == 1
    assert "HEAD is" in result.stderr


def test_pre_push_guard_blocks_when_pushed_commit_unknown(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    result = run_script("pre_push_guard.sh", cwd=repo, env=_approved())
    assert result.returncode == 1
    assert "cannot tell" in result.stderr


# ---------------------------------------------------------------- typography check


def test_typography_check_flags_a_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.md"
    bad.write_text("one " + chr(0x2014) + " two\n", encoding="utf-8")
    good = tmp_path / "good.md"
    good.write_text("one, two\n", encoding="utf-8")
    assert run_script("check_typography.sh", str(bad)).returncode == 1
    assert run_script("check_typography.sh", str(good)).returncode == 0


def test_typography_check_fails_closed_when_grep_errors(tmp_path: Path) -> None:
    fake = tmp_path / "bin"
    fake.mkdir()
    grep = fake / "grep"
    grep.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    grep.chmod(0o755)
    good = tmp_path / "good.md"
    good.write_text("one, two\n", encoding="utf-8")
    # Prepend the fake grep from inside bash, so PATH stays in bash's own format.
    script = str(SCRIPTS / "check_typography.sh")
    prepend = 'PATH="$(cd "$1" && pwd):$PATH"; shift; exec bash "$@"'
    result = run_bash(["-c", prepend, "_", str(fake), script, str(good)])
    assert result.returncode == 2, result.stdout + result.stderr
    assert "Failing closed" in result.stderr


def test_typography_check_passes_on_repo() -> None:
    result = run_script("check_typography.sh")
    assert result.returncode == 0, result.stdout + result.stderr


def test_owner_identity_matches_shellutil() -> None:
    owner = (Path(__file__).resolve().parents[2] / "scripts" / "lib" / "owner.sh").read_text()
    assert f'ARBITR_OWNER_NAME="{OWNER_NAME}"' in owner
    assert f'ARBITR_OWNER_EMAIL="{OWNER_EMAIL}"' in owner


def _web_edit(repo: Path, email: str) -> str:
    """A commit like one from GitHub's web editor: another name, GitHub as committer."""
    (repo / "x.txt").write_text("x\n", encoding="utf-8")
    git(repo, "add", "x.txt")
    env = {
        "GIT_AUTHOR_NAME": "Owner Full Name",
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": "GitHub",
        "GIT_COMMITTER_EMAIL": "noreply@github.com",
    }
    git(repo, "commit", "-q", "-m", "Update x.txt", env=env)
    return git(repo, "rev-parse", "HEAD").strip()


def test_check_commits_accepts_a_listed_web_edit(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    sha = _web_edit(repo, OWNER_EMAIL)
    assert run_script("check_commits.sh", cwd=repo, env=clean_env()).returncode == 1
    (repo / "scripts").mkdir(exist_ok=True)
    (repo / "scripts" / "commit-exceptions.txt").write_text(
        f"{sha}  a web edit\n", encoding="utf-8"
    )
    result = run_script("check_commits.sh", cwd=repo, env=clean_env())
    assert result.returncode == 0, result.stderr


def test_check_commits_still_needs_the_owner_email_for_a_listed_commit(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    sha = _web_edit(repo, "someone@example.com")
    (repo / "scripts").mkdir(exist_ok=True)
    (repo / "scripts" / "commit-exceptions.txt").write_text(
        f"{sha}  a web edit\n", encoding="utf-8"
    )
    result = run_script("check_commits.sh", cwd=repo, env=clean_env())
    assert result.returncode == 1
    assert "owner's email" in result.stderr
