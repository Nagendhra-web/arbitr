"""Credential providers: environment, owner-only files and chains."""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

import pytest

from arbitr.credentials import (
    ChainCredentials,
    CredentialError,
    EnvCredentials,
    FileCredentials,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_env_names_map_to_variables() -> None:
    env = EnvCredentials(environ={"ARBITR_CRED_STRIPE_LIVE": "v1"})
    assert env.get("stripe-live") == "v1"
    assert env.get("stripe.live") == "v1"


@pytest.mark.parametrize("name", ["", "UPPER", "../escape", "a b", "x" * 65])
def test_invalid_names_are_refused(name: str, tmp_path: Path) -> None:
    for provider in (EnvCredentials(environ={}), FileCredentials(tmp_path)):
        with pytest.raises(CredentialError, match="invalid credential name"):
            provider.get(name)


def test_a_missing_env_credential_is_an_error() -> None:
    with pytest.raises(CredentialError, match="not set"):
        EnvCredentials(environ={"ARBITR_CRED_X": ""}).get("x")


def write_secret(folder: Path, name: str, value: str) -> Path:
    path = folder / name
    path.write_text(value, encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    return path


def test_a_file_credential_is_read_without_its_newline(tmp_path: Path) -> None:
    write_secret(tmp_path, "stripe", "sk_value\n")
    assert FileCredentials(tmp_path).get("stripe") == "sk_value"


def test_a_missing_file_credential_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(CredentialError, match="cannot be read"):
        FileCredentials(tmp_path).get("absent")


def test_an_empty_file_credential_is_an_error(tmp_path: Path) -> None:
    write_secret(tmp_path, "blank", "\n")
    with pytest.raises(CredentialError, match="empty"):
        FileCredentials(tmp_path).get("blank")


def test_a_file_readable_by_others_is_refused_on_posix(tmp_path: Path) -> None:
    path = write_secret(tmp_path, "shared", "sk_value")
    if sys.platform == "win32":  # Windows has no group or other mode bits to check
        assert FileCredentials(tmp_path).get("shared") == "sk_value"
        return
    os.chmod(path, 0o644)
    with pytest.raises(CredentialError, match="readable by other users"):
        FileCredentials(tmp_path).get("shared")


def test_a_chain_uses_the_first_provider_that_has_it(tmp_path: Path) -> None:
    write_secret(tmp_path, "stripe", "from-file")
    chain = ChainCredentials(
        [EnvCredentials(environ={"ARBITR_CRED_OTHER": "o"}), FileCredentials(tmp_path)]
    )
    assert chain.get("stripe") == "from-file"
    assert chain.get("other") == "o"
    with pytest.raises(CredentialError, match="any provider"):
        chain.get("nowhere")
