"""The pytest plugin: fixtures for a throwaway ledger and run. Loaded when Arbitr is installed.

Fixtures:

- ``arbitr_policy``: the policy the ledger uses. By default the file named by
  the ``arbitr_policy`` ini option (relative to the rootdir), or Arbitr's
  default policy. Override the fixture to return a ``Policy``, a path or
  YAML text.
- ``arbitr_ledger``: a ledger in the test's temporary folder, closed after the test.
- ``arbitr_run``: a run on that ledger (principal ``test-user``, agent
  ``test-agent``), active for the whole test. Pass it to the assertions in
  ``arbitr.testing``.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

    from arbitr.executor import Ledger
    from arbitr.policy.schema import Policy
    from arbitr.testing.assertions import TestRun

# Arbitr modules are imported inside the fixtures: pytest loads this plugin
# before coverage starts, and a project that never uses the fixtures should
# not import the ledger at all.

PRINCIPAL = "test-user"
AGENT_ID = "test-agent"


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the ``arbitr_policy`` ini option."""
    parser.addini("arbitr_policy", "policy file for the arbitr_ledger fixture", default="")


def as_policy(value: Policy | str | Path) -> Policy:
    """A policy from a ``Policy``, a path to a policy file, or YAML text."""
    from arbitr.policy.schema import Policy, load_policy  # noqa: PLC0415 - see above

    if isinstance(value, Policy):
        return value
    if isinstance(value, Path):
        return load_policy(value)
    text = value.strip()
    if "\n" not in text and text.endswith((".yaml", ".yml")):
        return load_policy(Path(text))
    return load_policy(value)


@pytest.fixture
def arbitr_policy(request: pytest.FixtureRequest) -> Policy | str | Path:
    """The policy for ``arbitr_ledger``. Override this fixture to choose one."""
    configured = str(request.config.getini("arbitr_policy") or "")
    if configured:
        return Path(request.config.rootpath) / configured
    return "version: 1\n"


@pytest.fixture
def arbitr_ledger(tmp_path: Path, arbitr_policy: Policy | str | Path) -> Iterator[Ledger]:
    """A ledger in the test's temporary folder with ``arbitr_policy``."""
    from arbitr.executor import Ledger  # noqa: PLC0415 - see above

    path = tmp_path / "arbitr-test-ledger.db"
    with Ledger.open(path, as_policy(arbitr_policy), key=secrets.token_bytes(32)) as ledger:
        yield ledger


@pytest.fixture
def arbitr_run(arbitr_ledger: Ledger) -> Iterator[TestRun]:
    """A run on ``arbitr_ledger`` that stays active for the whole test."""
    from arbitr.testing.assertions import TestRun  # noqa: PLC0415 - see above

    with arbitr_ledger.run(principal=PRINCIPAL, agent_id=AGENT_ID) as handle:
        yield TestRun(arbitr_ledger, handle.run_id)
