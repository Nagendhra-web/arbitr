"""Nox sessions: the Python version matrix for local CI.

Interpreters come from uv, so no system Pythons are needed. Each session gets
the exact locked dependency set.
"""

from __future__ import annotations

import nox

nox.options.default_venv_backend = "uv"
nox.options.error_on_missing_interpreters = True

PYTHONS = ["3.11", "3.12", "3.13"]


@nox.session(python=PYTHONS)
def tests(session: nox.Session) -> None:
    """Run the unit, property and repo suites on one Python version."""
    session.run_install(
        "uv",
        "sync",
        "--locked",
        "--all-extras",
        f"--python={session.virtualenv.location}",
        env={"UV_PROJECT_ENVIRONMENT": session.virtualenv.location},
    )
    paths = [p for p in ("tests/unit", "tests/property", "tests/repo") if _has_tests(p)]
    session.run("pytest", "-p", "no:cacheprovider", "-q", "-n", "auto", *paths, *session.posargs)


def _has_tests(path: str) -> bool:
    from pathlib import Path  # noqa: PLC0415

    return any(Path(path).rglob("test_*.py"))
