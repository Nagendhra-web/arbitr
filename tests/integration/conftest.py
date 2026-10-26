"""Fixtures for the framework adapter tests: a ledger and fake payments."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from bench.fakes.payments import FakePayments

from adapter_support import KEY, POLICY
from arbitr.executor import Ledger

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "ledger.db", POLICY, key=KEY, worker_id="w1") as led:
        yield led


@pytest.fixture
def payments() -> Iterator[FakePayments]:
    service = FakePayments(native=True)
    yield service
    service.close()
