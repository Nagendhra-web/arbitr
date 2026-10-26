"""Configuration: loading arbitr.yaml, environment overrides, keys and project setup."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import keyring.core
import pytest

from arbitr import config as config_module
from arbitr.config import (
    CONFIG_FILE,
    Config,
    ConfigError,
    EnvSource,
    FileSource,
    KeyringSource,
    init_project,
    load_config,
)
from arbitr.core.errors import ArbitrError
from arbitr.credentials import ChainCredentials, CredentialError
from arbitr.executor import Ledger
from fake_keyring import FakeKeyring

KEY_HEX = "ab" * 32


def write_key(path: Path, text: str = KEY_HEX + "\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    return path


def write_config(folder: Path, text: str) -> Path:
    path = folder / CONFIG_FILE
    path.write_text(text, encoding="utf-8")
    return path


def project(tmp_path: Path, extra: str = "") -> Path:
    """A minimal valid project: config, policy and key file."""
    (tmp_path / "policy.yaml").write_text("version: 1\n", encoding="utf-8")
    write_key(tmp_path / ".arbitr" / "key")
    return write_config(tmp_path, "version: 1\n" + extra)


# ------------------------------------------------------------ loading


def test_defaults_resolve_against_the_config_folder(tmp_path: Path) -> None:
    cfg = load_config(project(tmp_path), environ={})
    assert cfg.source == tmp_path / CONFIG_FILE
    assert cfg.ledger == tmp_path / ".arbitr" / "ledger.db"
    assert cfg.policy == tmp_path / "policy.yaml"
    assert cfg.key_file == tmp_path / ".arbitr" / "key"
    assert cfg.worker_id is None
    assert (cfg.lease_ttl, cfg.approval_ttl) == (30.0, None)
    assert cfg.credentials == (EnvSource(),)
    assert cfg.approvals.webhook_url is None
    assert cfg.approvals.link_base_url is None


def test_every_field_can_be_set(tmp_path: Path) -> None:
    absolute = tmp_path / "elsewhere" / "ledger.db"
    path = project(
        tmp_path,
        f"ledger: {absolute.as_posix()}\n"
        "policy: rules/main.yaml\n"
        "key_file: keys/ledger.key\n"
        "worker_id: worker-1\n"
        "lease_ttl: 45s\n"
        "approval_ttl: 2.5\n"
        "credentials:\n"
        "  - env\n"
        "  - file: secrets\n"
        "  - keyring: arbitr-prod\n"
        "approvals:\n"
        "  webhook_url: https://hooks.example.com/arbitr\n"
        "  link_base_url: http://127.0.0.1:8484\n",
    )
    cfg = load_config(path, environ={})
    assert cfg.ledger == absolute
    assert cfg.policy == tmp_path / "rules" / "main.yaml"
    assert cfg.key_file == tmp_path / "keys" / "ledger.key"
    assert cfg.worker_id == "worker-1"
    assert (cfg.lease_ttl, cfg.approval_ttl) == (45.0, 2.5)
    assert cfg.credentials == (
        EnvSource(),
        FileSource(kind="file", folder=tmp_path / "secrets"),
        KeyringSource(kind="keyring", service="arbitr-prod"),
    )
    assert cfg.approvals.webhook_url == "https://hooks.example.com/arbitr"
    assert cfg.approvals.link_base_url == "http://127.0.0.1:8484"


def test_the_config_is_frozen(tmp_path: Path) -> None:
    cfg = load_config(project(tmp_path), environ={})
    with pytest.raises(ValueError, match="frozen"):
        cfg.worker_id = "x"  # type: ignore[misc]


def test_arbitr_config_names_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = project(tmp_path)
    monkeypatch.chdir(tmp_path.parent)
    assert load_config(environ={"ARBITR_CONFIG": str(path)}).source == path


def test_the_path_argument_beats_arbitr_config(tmp_path: Path) -> None:
    path = project(tmp_path)
    cfg = load_config(path, environ={"ARBITR_CONFIG": str(tmp_path / "missing.yaml")})
    assert cfg.source == path


def test_the_default_file_is_arbitr_yaml_in_the_working_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ARBITR_CONFIG", raising=False)
    assert load_config().source == tmp_path / CONFIG_FILE


def test_environment_overrides_beat_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = project(tmp_path, "ledger: from-file.db\npolicy: from-file.yaml\n")
    elsewhere = tmp_path / "cwd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    cfg = load_config(
        path,
        environ={
            "ARBITR_LEDGER": "env.db",
            "ARBITR_POLICY": str(tmp_path / "env-policy.yaml"),
            "ARBITR_KEY_FILE": "env.key",
        },
    )
    assert cfg.ledger == elsewhere / "env.db"  # relative env paths use the working folder
    assert cfg.policy == tmp_path / "env-policy.yaml"
    assert cfg.key_file == elsewhere / "env.key"


def test_empty_environment_values_are_ignored(tmp_path: Path) -> None:
    cfg = load_config(project(tmp_path), environ={"ARBITR_LEDGER": "", "ARBITR_CONFIG": ""})
    assert cfg.ledger == tmp_path / ".arbitr" / "ledger.db"


def test_a_missing_config_file_says_how_to_create_one(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"does not exist.*arbitr init") as exc:
        load_config(tmp_path / CONFIG_FILE, environ={})
    assert isinstance(exc.value, ArbitrError)
    assert exc.value.code == "invalid_config"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("version: 1\nversion: 1\n", "duplicate key"),
        ("version: [1\n", "not valid YAML"),
        ("- version\n", "must be a mapping"),
        ("", "must be a mapping"),
        ("version: 2\n", "version"),
        ("version: 1\nledgr: x.db\n", "ledgr"),
        ("version: 1\nlease_ttl: 0\n", "lease_ttl"),
        ("version: 1\nlease_ttl: soon\n", "lease_ttl: invalid duration"),
        ("version: 1\napproval_ttl: true\n", "approval_ttl"),
        ("version: 1\nworker_id: ''\n", "worker_id"),
        ("version: 1\ncredentials: [vault]\n", "credentials.0"),
        ("version: 1\ncredentials: [{file: a, keyring: b}]\n", "credentials.0"),
        ("version: 1\ncredentials: [{keyring: ' '}]\n", "credentials.0"),
        ("version: 1\ncredentials: [{env: x}]\n", "credentials.0"),
        ("version: 1\napprovals: {webhook_url: ftp://x}\n", "approvals.webhook_url"),
        ("version: 1\napprovals: {link_base_url: 'https://'}\n", "approvals.link_base_url"),
        ("version: 1\napprovals: {other: 1}\n", "approvals.other"),
    ],
)
def test_invalid_files_name_the_field_and_the_file(tmp_path: Path, text: str, message: str) -> None:
    path = write_config(tmp_path, text)
    with pytest.raises(ConfigError, match=message) as exc:
        load_config(path, environ={})
    assert str(path) in str(exc.value)


def test_a_key_in_the_config_file_is_refused(tmp_path: Path) -> None:
    path = write_config(tmp_path, f"version: 1\nledger_key: {KEY_HEX}\n")
    with pytest.raises(ConfigError, match="never put the ledger key") as exc:
        load_config(path, environ={})
    assert KEY_HEX not in str(exc.value)


# ------------------------------------------------------------ keys


def test_the_key_comes_from_the_key_file(tmp_path: Path) -> None:
    assert load_config(project(tmp_path), environ={}).key() == bytes.fromhex(KEY_HEX)


def test_the_environment_key_beats_the_key_file(tmp_path: Path) -> None:
    env_key = "cd" * 40
    cfg = load_config(project(tmp_path), environ={"ARBITR_LEDGER_KEY": env_key})
    assert cfg.key() == bytes.fromhex(env_key)
    assert env_key not in repr(cfg)
    assert env_key not in cfg.model_dump_json()


@pytest.mark.parametrize(
    ("value", "message"),
    [("zz" * 32, "not valid hex"), ("ab" * 31, "at least 32 bytes")],
)
def test_a_bad_environment_key_is_refused_without_showing_it(
    tmp_path: Path, value: str, message: str
) -> None:
    cfg = load_config(project(tmp_path), environ={"ARBITR_LEDGER_KEY": value})
    with pytest.raises(ConfigError, match=message) as exc:
        cfg.key()
    assert value not in str(exc.value)
    assert "ARBITR_LEDGER_KEY" in str(exc.value)


def test_a_missing_key_file_names_the_field(tmp_path: Path) -> None:
    path = project(tmp_path, "key_file: absent.key\n")
    with pytest.raises(ConfigError, match=r"key_file .*absent.key does not exist") as exc:
        load_config(path, environ={}).key()
    assert str(path) in str(exc.value)


def test_an_unreadable_key_file_is_reported(tmp_path: Path) -> None:
    (tmp_path / "keydir").mkdir(mode=0o700)
    path = project(tmp_path, "key_file: keydir\n")
    with pytest.raises(ConfigError, match="cannot be read"):
        load_config(path, environ={}).key()


@pytest.mark.parametrize(
    ("text", "message"),
    [("not hex\n", "hex"), ("ab" * 16, "at least 32 bytes"), ("\xe9", "hex")],
)
def test_a_bad_key_file_is_refused_without_showing_it(
    tmp_path: Path, text: str, message: str
) -> None:
    path = project(tmp_path)
    key_file = tmp_path / ".arbitr" / "key"
    key_file.write_bytes(text.encode("latin-1"))
    with pytest.raises(ConfigError, match=message) as exc:
        load_config(path, environ={}).key()
    assert "key_file" in str(exc.value)
    assert text.strip() not in str(exc.value)


def test_a_key_file_readable_by_others_is_refused_on_posix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = load_config(project(tmp_path), environ={})
    key_file = tmp_path / ".arbitr" / "key"
    if sys.platform == "win32":  # Windows has no group or other mode bits to check
        assert cfg.key() == bytes.fromhex(KEY_HEX)
    else:
        os.chmod(key_file, 0o644)
        with pytest.raises(ConfigError, match="readable by other users"):
            cfg.key()
    # The check itself, forced on, so it runs on every platform.
    monkeypatch.setattr(config_module, "_CHECK_MODE", True)
    if sys.platform != "win32":
        os.chmod(key_file, 0o640)
    with pytest.raises(ConfigError, match="chmod 600"):
        cfg.key()


# ------------------------------------------------------------ credentials and ledger


def test_no_credential_sources_means_no_provider(tmp_path: Path) -> None:
    cfg = load_config(project(tmp_path, "credentials: []\n"), environ={})
    assert cfg.credential_provider() is None


def test_the_credential_chain_follows_the_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    write_key(secrets / "github", "from-file")
    monkeypatch.setattr(
        keyring.core, "_keyring_backend", FakeKeyring({("svc", "stripe"): "from-keyring"})
    )
    path = project(tmp_path, "credentials: [env, {file: secrets}, {keyring: svc}]\n")
    cfg = load_config(path, environ={"ARBITR_CRED_SLACK": "from-env"})
    provider = cfg.credential_provider()
    assert isinstance(provider, ChainCredentials)
    assert provider.get("slack") == "from-env"
    assert provider.get("github") == "from-file"
    assert provider.get("stripe") == "from-keyring"
    with pytest.raises(CredentialError):
        provider.get("absent")


def test_open_ledger_uses_every_setting(tmp_path: Path) -> None:
    path = project(tmp_path, "worker_id: w1\nlease_ttl: 1m\napproval_ttl: 10m\n")
    cfg = load_config(path, environ={})
    with cfg.open_ledger() as ledger:
        assert isinstance(ledger, Ledger)
        assert ledger.path == cfg.ledger
        assert (ledger.worker_id, ledger.lease_ttl, ledger.approval_ttl) == ("w1", 60.0, 600.0)
        assert ledger.credentials is not None
        assert ledger.verify().ok
    assert cfg.ledger.is_file()


def test_open_ledger_reports_a_bad_policy(tmp_path: Path) -> None:
    path = project(tmp_path)
    (tmp_path / "policy.yaml").write_text("version: 1\nmode: loud\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"policy .*policy.yaml"):
        load_config(path, environ={}).open_ledger()


def test_open_ledger_reports_a_missing_policy(tmp_path: Path) -> None:
    path = project(tmp_path, "policy: absent.yaml\n")
    with pytest.raises(ConfigError, match=r"policy .*absent.yaml cannot be read"):
        load_config(path, environ={}).open_ledger()


def test_open_ledger_reports_a_ledger_that_cannot_open(tmp_path: Path) -> None:
    path = project(tmp_path, "ledger: ledger.db\n")
    (tmp_path / "ledger.db").write_bytes(b"this is not a sqlite database at all" * 4)
    with pytest.raises(ConfigError, match=r"ledger .*ledger.db cannot be opened"):
        load_config(path, environ={}).open_ledger()


# ------------------------------------------------------------ check


def test_check_passes_on_a_good_project(tmp_path: Path) -> None:
    cfg = load_config(project(tmp_path), environ={})
    cfg.open_ledger().close()
    assert cfg.check() == []


def test_check_lists_every_problem_without_creating_the_ledger(tmp_path: Path) -> None:
    path = project(tmp_path, "key_file: absent.key\ncredentials: [{file: nowhere}]\n")
    (tmp_path / "policy.yaml").write_text("version: 2\n", encoding="utf-8")
    problems = load_config(path, environ={}).check()
    assert len(problems) == 3
    assert any("policy" in p for p in problems)
    assert any("key_file" in p for p in problems)
    assert any("nowhere" in p and "credentials" in p for p in problems)
    assert not (tmp_path / ".arbitr" / "ledger.db").exists()


def test_check_reports_a_missing_ledger(tmp_path: Path) -> None:
    problems = load_config(project(tmp_path), environ={}).check()
    assert len(problems) == 1
    assert "does not exist" in problems[0]
    assert "arbitr init" in problems[0]


def test_check_reports_a_broken_audit_chain(tmp_path: Path) -> None:
    cfg = load_config(project(tmp_path), environ={})
    with cfg.open_ledger() as ledger, ledger.run("p", "a"):
        pass
    conn = sqlite3.connect(cfg.ledger)
    with conn:
        conn.execute("UPDATE events SET payload = '{}'")
    conn.close()
    problems = cfg.check()
    assert len(problems) == 1
    assert "audit chain" in problems[0].lower()


def test_check_reports_a_ledger_that_cannot_open(tmp_path: Path) -> None:
    cfg = load_config(project(tmp_path), environ={})
    cfg.ledger.write_bytes(b"garbage" * 20)
    problems = cfg.check()
    assert len(problems) == 1
    assert "cannot be opened" in problems[0]


def test_check_reports_a_missing_keyring_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = load_config(project(tmp_path, "credentials: [{keyring: svc}]\n"), environ={})
    cfg.open_ledger().close()
    monkeypatch.setattr(config_module, "find_spec", lambda name: None)
    problems = cfg.check()
    hint = 'The keyring provider needs the "keyring" extra: pip install "arbitr[keyring]"'
    assert problems == [f"credentials (config {cfg.source}): {hint}"]


def test_a_config_built_in_code_has_no_source(tmp_path: Path) -> None:
    write_key(tmp_path / "k")
    cfg = Config(version=1, key_file=tmp_path / "k")
    assert cfg.source is None
    assert cfg.key() == bytes.fromhex(KEY_HEX)
    with pytest.raises(ConfigError, match="key_file") as exc:
        Config(version=1, key_file=tmp_path / "absent").key()
    assert "(config" not in str(exc.value)


# ------------------------------------------------------------ init


def test_init_writes_a_working_project(tmp_path: Path) -> None:
    result = init_project(tmp_path, packs=("databases", "git"))
    assert result.config == tmp_path / CONFIG_FILE
    assert result.ledger_created
    assert result.gitignore == "missing"
    assert result.packs == ("databases", "git")
    cfg = load_config(result.config, environ={})
    assert cfg.ledger == result.ledger
    assert cfg.key_file == result.key_file
    assert len(cfg.key()) == 32
    assert cfg.check() == []
    policy = (tmp_path / "policy.yaml").read_text(encoding="utf-8")
    assert "include: [databases, git]" in policy
    if sys.platform != "win32":
        assert result.key_file.stat().st_mode & 0o777 == 0o600


def test_init_makes_a_new_key_each_time(tmp_path: Path) -> None:
    first = init_project(tmp_path / "a").key_file.read_text(encoding="ascii")
    second = init_project(tmp_path / "b").key_file.read_text(encoding="ascii")
    assert first != second


def test_init_without_packs_writes_an_empty_include(tmp_path: Path) -> None:
    init_project(tmp_path)
    assert "include: []" in (tmp_path / "policy.yaml").read_text(encoding="utf-8")


def test_init_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    init_project(tmp_path)
    before = (tmp_path / ".arbitr" / "key").read_bytes()
    with pytest.raises(ConfigError, match=r"already exist.*--force"):
        init_project(tmp_path)
    assert (tmp_path / ".arbitr" / "key").read_bytes() == before


def test_init_with_force_replaces_files_and_keeps_the_ledger(tmp_path: Path) -> None:
    first = init_project(tmp_path)
    before = first.key_file.read_bytes()
    (tmp_path / "policy.yaml").write_text("version: 1\nmode: shadow\n", encoding="utf-8")
    second = init_project(tmp_path, packs=("git",), force=True)
    assert not second.ledger_created
    assert second.key_file.read_bytes() != before
    assert "include: [git]" in (tmp_path / "policy.yaml").read_text(encoding="utf-8")
    assert load_config(second.config, environ={}).check() == []


def test_init_refuses_unknown_packs_before_writing(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown pack 'nope'"):
        init_project(tmp_path, packs=("git", "nope"))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("before", "after", "status"),
    [
        ("node_modules/\n", "node_modules/\n.arbitr/\n", "added"),
        ("node_modules/", "node_modules/\n.arbitr/\n", "added"),
        ("", ".arbitr/\n", "added"),
        ("/.arbitr\n", "/.arbitr\n", "present"),
    ],
)
def test_init_keeps_the_key_out_of_git(
    tmp_path: Path, before: str, after: str, status: str
) -> None:
    (tmp_path / ".gitignore").write_text(before, encoding="utf-8")
    assert init_project(tmp_path).gitignore == status
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8") == after


def test_init_ignores_the_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARBITR_LEDGER", str(tmp_path / "env.db"))
    result = init_project(tmp_path / "proj")
    assert result.ledger == tmp_path / "proj" / ".arbitr" / "ledger.db"
    assert not (tmp_path / "env.db").exists()


def test_the_approval_time_comes_from_the_policy_unless_set(tmp_path: Path) -> None:
    from arbitr.config import init_project  # noqa: PLC0415

    init_project(tmp_path, packs=(), force=False)
    (tmp_path / "policy.yaml").write_text(
        "version: 1\napproval: { expires_after: 2m }\n", encoding="utf-8"
    )
    cfg = load_config(tmp_path / "arbitr.yaml", environ={})
    assert cfg.approval_ttl is None
    with cfg.open_ledger() as ledger:
        assert ledger.approval_ttl == 120.0


def test_a_webhook_announces_approvals_to_the_named_approvers(tmp_path: Path) -> None:
    from arbitr.approvals import WebhookNotifier  # noqa: PLC0415
    from arbitr.config import init_project  # noqa: PLC0415

    init_project(tmp_path, packs=(), force=False)
    path = tmp_path / "arbitr.yaml"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "approvals:\n  webhook_url: https://hooks.example.com/x\n"
        "  link_base_url: https://arbitr.example.com\n"
        "  approvers: { bob: [finance], carol: [] }\n",
        encoding="utf-8",
    )
    with load_config(path, environ={}).open_ledger() as ledger:
        notifier = ledger.notifier
    assert isinstance(notifier, WebhookNotifier)
    assert notifier.approvers == {"bob": ("finance",), "carol": ()}


def test_a_webhook_needs_a_link_base_url(tmp_path: Path) -> None:
    path = tmp_path / "arbitr.yaml"
    path.write_text("version: 1\napprovals: { webhook_url: https://hooks.example.com/x }\n",
                    encoding="utf-8")  # fmt: skip
    with pytest.raises(ConfigError, match="link_base_url"):
        load_config(path, environ={})
