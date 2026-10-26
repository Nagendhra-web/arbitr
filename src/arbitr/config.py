"""Configuration: one ``arbitr.yaml`` file plus ``ARBITR_*`` environment overrides.

A config file looks like this (every field except ``version`` is optional)::

    version: 1
    ledger: .arbitr/ledger.db      # the SQLite ledger
    policy: policy.yaml            # the policy file
    key_file: .arbitr/key          # the ledger HMAC key, as hex, owner-only
    worker_id: worker-1            # default: host name plus a random suffix
    lease_ttl: 30s                 # seconds, or a number with s, m, h or d
    approval_ttl: 15m
    credentials:                   # tried in this order
      - env                        # ARBITR_CRED_<NAME> variables
      - file: secrets              # one owner-only file per credential
      - keyring: arbitr            # the OS keyring (needs the keyring extra)
    approvals:
      webhook_url: https://hooks.example.com/arbitr
      link_base_url: https://arbitr.example.com

Relative paths in the file are resolved against the file's folder.

Which file is read:

1. the ``path`` given to ``load_config`` (``--config`` on the command line),
2. else ``ARBITR_CONFIG``,
3. else ``arbitr.yaml`` in the working folder.

Precedence for each setting: environment over file over defaults.

- ``ARBITR_LEDGER``, ``ARBITR_POLICY`` and ``ARBITR_KEY_FILE`` replace
  ``ledger``, ``policy`` and ``key_file``. Relative paths in these variables
  are resolved against the working folder.
- ``ARBITR_LEDGER_KEY`` holds the key as hex and is used instead of the key
  file. The key never goes in the config file.
- An empty variable counts as unset.

The key must be at least 32 bytes. On POSIX systems a key file that group or
others can read is refused.

Example:
    >>> cfg = Config(version=1)
    >>> cfg.lease_ttl, cfg.credentials
    (30.0, (EnvSource(kind='env'),))
"""

from __future__ import annotations

import os
import secrets
import stat
import sys
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal, Unpack
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from arbitr.core.errors import ArbitrError, PolicyError, StorageError
from arbitr.core.redact import MIN_KEY_BYTES
from arbitr.credentials import (
    KEYRING_HINT,
    ChainCredentials,
    CredentialProvider,
    EnvCredentials,
    FileCredentials,
    KeyringCredentials,
)
from arbitr.policy.schema import format_errors, load_policy, load_yaml, parse_duration

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from arbitr.approvals import ApprovalNotifier
    from arbitr.executor import Ledger, LedgerOptions
    from arbitr.policy.schema import Policy

CONFIG_FILE: Final = "arbitr.yaml"
POLICY_FILE: Final = "policy.yaml"
DATA_DIR: Final = ".arbitr"
ENV_CONFIG: Final = "ARBITR_CONFIG"
ENV_LEDGER_KEY: Final = "ARBITR_LEDGER_KEY"
ENV_PATHS: Final = {
    "ARBITR_LEDGER": "ledger",
    "ARBITR_POLICY": "policy",
    "ARBITR_KEY_FILE": "key_file",
}
_CHECK_MODE: bool = sys.platform != "win32"
"""Whether key file permissions are checked. Windows has no group or other mode bits."""


class ConfigError(ArbitrError, ValueError):
    """The configuration is missing, invalid or unsafe. Nothing starts."""

    code = "invalid_config"


def _seconds(value: object) -> float:
    """A positive number of seconds from ``30``, ``2.5`` or ``30s``, ``15m``, ``2h``, ``1d``."""
    if isinstance(value, bool):
        raise ValueError("give a number of seconds or a duration such as 30s")  # noqa: TRY004
    seconds = float(value) if isinstance(value, float) else parse_duration(value).total_seconds()
    if seconds <= 0:
        raise ValueError("must be more than zero")
    return seconds


Seconds = Annotated[float, BeforeValidator(_seconds)]


def _resolve(value: Path, info: ValidationInfo) -> Path:
    base = (info.context or {}).get("base")
    return value if value.is_absolute() or base is None else Path(base) / value


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", validate_default=True)


class EnvSource(_Model):
    """Credentials from ``ARBITR_CRED_<NAME>`` environment variables."""

    kind: Literal["env"] = "env"


class FileSource(_Model):
    """Credentials from owner-only files in ``folder``."""

    kind: Literal["file"]
    folder: Path

    @field_validator("folder")
    @classmethod
    def _resolve_folder(cls, value: Path, info: ValidationInfo) -> Path:
        return _resolve(value, info)


class KeyringSource(_Model):
    """Credentials from the OS keyring under ``service``."""

    kind: Literal["keyring"]
    service: str = Field(min_length=1, pattern=r"\S")


CredentialSource = Annotated[EnvSource | FileSource | KeyringSource, Field(discriminator="kind")]

_SOURCE_HELP: Final = "a credentials entry is env, {file: <folder>} or {keyring: <service>}"


def _source(value: object) -> object:
    """``env``, ``{file: x}`` or ``{keyring: x}`` to the tagged form the models read."""
    if value == "env":
        return {"kind": "env"}
    if isinstance(value, dict) and len(value) == 1:
        ((kind, arg),) = value.items()
        if kind == "file":
            return {"kind": "file", "folder": arg}
        if kind == "keyring":
            return {"kind": "keyring", "service": arg}
    if isinstance(value, EnvSource | FileSource | KeyringSource):
        return value
    raise ValueError(_SOURCE_HELP)


def _http_url(value: str | None) -> str | None:
    if value is None:
        return None
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("must be an http or https URL with a host")
    return value


class ApprovalsConfig(_Model):
    """Where approval requests are announced, and who gets signed links in them."""

    webhook_url: Annotated[str | None, BeforeValidator(_http_url)] = None
    link_base_url: Annotated[str | None, BeforeValidator(_http_url)] = None
    approvers: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    """Approver names and their roles, for signed links."""
    approver_webhooks: dict[str, Annotated[str, BeforeValidator(_http_url)]] = Field(
        default_factory=dict
    )
    """Each approver's own webhook URL. Only there do their signed links go when
    an approval needs more than one person."""

    @model_validator(mode="after")
    def _links_need_a_base(self) -> ApprovalsConfig:
        if self.webhook_url is not None and self.link_base_url is None:
            raise ValueError("a webhook_url needs a link_base_url for the signed links")
        return self

    def notifier(self) -> ApprovalNotifier | None:
        """The webhook channel, when a webhook URL is configured."""
        if self.webhook_url is None or self.link_base_url is None:
            return None
        from arbitr.approvals import WebhookNotifier  # noqa: PLC0415

        return WebhookNotifier(self.webhook_url, link_base_url=self.link_base_url,
                               approvers=self.approvers,
                               approver_urls=self.approver_webhooks)  # fmt: skip


class Config(_Model):
    """A validated configuration. Build it with ``load_config``."""

    version: Literal[1]
    ledger: Path = Path(DATA_DIR) / "ledger.db"
    policy: Path = Path(POLICY_FILE)
    key_file: Path = Path(DATA_DIR) / "key"
    worker_id: str | None = Field(default=None, min_length=1, max_length=128)
    lease_ttl: Seconds = 30.0
    approval_ttl: Seconds | None = None
    """How long an approval request stays open; None means the policy's approval.expires_after."""
    credentials: tuple[Annotated[CredentialSource, BeforeValidator(_source)], ...] = (EnvSource(),)
    approvals: ApprovalsConfig = ApprovalsConfig()

    _source: Path | None = PrivateAttr(default=None)
    _key_hex: str | None = PrivateAttr(default=None)
    _environ: Mapping[str, str] | None = PrivateAttr(default=None)

    @field_validator("ledger", "policy", "key_file")
    @classmethod
    def _resolve_path(cls, value: Path, info: ValidationInfo) -> Path:
        return _resolve(value, info)

    @property
    def source(self) -> Path | None:
        """The config file this came from, or None for a config built in code."""
        return self._source

    def _where(self, field: str) -> str:
        return field if self._source is None else f"{field} (config {self._source})"

    def key(self) -> bytes:
        """The ledger HMAC key: ``ARBITR_LEDGER_KEY`` if set, else the key file.

        Raises:
            ConfigError: the key is missing, not hex, shorter than 32 bytes, or
                in a file that other users can read. The key is never shown.
        """
        if self._key_hex is not None:
            return _decode_key(self._key_hex, ENV_LEDGER_KEY)
        return _decode_key(self._read_key_file(), f"{self._where('key_file')} {self.key_file}")

    def _read_key_file(self) -> str:
        path, where = self.key_file, self._where("key_file")
        try:
            info = path.stat()
            if _CHECK_MODE and info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ConfigError(
                    f"{where} {path} is readable by other users: run chmod 600 {path}"
                )
            data = path.read_bytes()
        except FileNotFoundError:
            raise ConfigError(
                f"{where} {path} does not exist: run 'arbitr init' or set {ENV_LEDGER_KEY}"
            ) from None
        except OSError as exc:
            raise ConfigError(f"{where} {path} cannot be read: {exc.strerror}") from None
        try:
            return data.decode("ascii")
        except UnicodeDecodeError:
            return "?"  # not hex; _decode_key says so without showing the bytes

    def credential_provider(self) -> CredentialProvider | None:
        """The providers from ``credentials`` as one chain, or None when the list is empty."""
        if not self.credentials:
            return None
        return ChainCredentials([self._provider(s) for s in self.credentials])

    def _provider(self, source: EnvSource | FileSource | KeyringSource) -> CredentialProvider:
        if isinstance(source, FileSource):
            return FileCredentials(source.folder)
        if isinstance(source, KeyringSource):
            return KeyringCredentials(source.service)
        return EnvCredentials(self._environ)

    def load_policy(self) -> Policy:
        """Load and validate the policy file.

        Raises:
            ConfigError: the file cannot be read or is not a valid policy.
        """
        where = f"{self._where('policy')} {self.policy}"
        try:
            return load_policy(self.policy)
        except OSError as exc:
            raise ConfigError(f"{where} cannot be read: {exc.strerror}") from None
        except PolicyError as exc:
            raise ConfigError(f"{where}: {exc}") from exc

    def open_ledger(self, **options: Unpack[LedgerOptions]) -> Ledger:
        """Open (or create) the ledger with the policy, key and credentials from this config.

        ``options`` go to ``Ledger.open`` and win over the config.

        Raises:
            ConfigError: the policy, key or ledger is unusable. The message says which.
        """
        from arbitr.executor import Ledger  # noqa: PLC0415 - the executor imports this module

        settings: LedgerOptions = {
            "worker_id": self.worker_id,
            "lease_ttl": self.lease_ttl,
            "approval_ttl": self.approval_ttl,
            "credentials": self.credential_provider(),
            "notifier": self.approvals.notifier(),
            "protected_paths": self.protected_paths(),
        }
        policy, key = self.load_policy(), self.key()
        try:
            self.ledger.parent.mkdir(parents=True, exist_ok=True)
            settings.update(options)  # options win over the config
            return Ledger.open(self.ledger, policy, key=key, **settings)
        except (StorageError, OSError) as exc:
            where = f"{self._where('ledger')} {self.ledger}"
            raise ConfigError(f"{where} cannot be opened: {exc}") from exc

    def protected_paths(self) -> tuple[Path, ...]:
        """Files agents may never touch: the key, the policy and this config (and the ledger)."""
        paths = [self.ledger, self.policy, self.key_file]
        if self.source is not None:
            paths.append(Path(self.source))
        return tuple(paths)

    def check(self) -> list[str]:
        """Validate the policy, key, credential sources and ledger without running anything.

        The ledger is opened and its audit chain verified only when it exists
        and the policy and key are usable; a missing ledger is a problem, not
        created. Returns the problems, empty when everything is usable.
        """
        problems = [p for p in (self._problem(self.load_policy), self._problem(self.key)) if p]
        problems += self._credential_problems()
        if not problems:
            problems += self._ledger_problems()
        return problems

    @staticmethod
    def _problem(step: Callable[[], object]) -> str | None:
        try:
            step()
        except ConfigError as exc:
            return str(exc)
        return None

    def _credential_problems(self) -> list[str]:
        where = self._where("credentials")
        problems = []
        for source in self.credentials:
            if isinstance(source, FileSource) and not source.folder.is_dir():
                problems.append(f"{where}: folder {source.folder} does not exist")
            if isinstance(source, KeyringSource) and find_spec("keyring") is None:
                problems.append(f"{where}: {KEYRING_HINT}")
        return problems

    def _ledger_problems(self) -> list[str]:
        where = f"{self._where('ledger')} {self.ledger}"
        if not self.ledger.is_file():
            return [f"{where} does not exist: run 'arbitr init' to create it"]
        try:
            with self.open_ledger() as ledger:
                result = ledger.verify()
        except (ConfigError, StorageError) as exc:
            return [str(exc)]
        return [] if result.ok else [f"{where}: {result.describe()}"]


def _decode_key(text: str, where: str) -> bytes:
    try:
        key = bytes.fromhex(text.strip())
    except ValueError:
        raise ConfigError(f"{where} is not valid hex: write the key as hex digits") from None
    if len(key) < MIN_KEY_BYTES:
        raise ConfigError(
            f"{where} is {len(key)} bytes; the key must be at least {MIN_KEY_BYTES} bytes"
            f" ({MIN_KEY_BYTES * 2} hex characters)"
        )
    return key


def _config_path(path: str | Path | None, env: Mapping[str, str]) -> Path:
    if path is not None:
        chosen = Path(path)
    elif env.get(ENV_CONFIG):
        chosen = Path(env[ENV_CONFIG])
    else:
        chosen = Path(CONFIG_FILE)
    return chosen if chosen.is_absolute() else Path.cwd() / chosen


def _read_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(
            f"config file {path} does not exist: run 'arbitr init' or set {ENV_CONFIG}"
        )
    try:
        data = load_yaml(path, f"config file {path}")
    except PolicyError as exc:
        raise ConfigError(f"config file {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must be a mapping with at least 'version: 1'")
    if "ledger_key" in data:
        raise ConfigError(
            f"config file {path}: never put the ledger key in the config file;"
            f" use key_file or {ENV_LEDGER_KEY}"
        )
    return data


def _env_overrides(env: Mapping[str, str]) -> dict[str, Path]:
    return {
        field: Path.cwd() / env[name]  # an absolute value stays absolute
        for name, field in ENV_PATHS.items()
        if env.get(name)
    }


def load_config(path: str | Path | None = None, environ: Mapping[str, str] | None = None) -> Config:
    """Read the config file, apply environment overrides and validate everything.

    ``environ`` defaults to the process environment; pass a mapping to test or
    to ignore it. It also feeds the ``env`` credential provider.

    Raises:
        ConfigError: the file is missing, not valid YAML, or has an invalid
            field. The message names the file and the field.
    """
    env = os.environ if environ is None else environ
    source = _config_path(path, env)
    data = {**_read_file(source), **_env_overrides(env)}
    try:
        config = Config.model_validate(data, context={"base": source.parent})
    except ValidationError as exc:
        raise ConfigError(format_errors(exc, f"config file {source}")) from None
    config._source = source
    config._key_hex = env.get(ENV_LEDGER_KEY) or None
    config._environ = environ
    return config


# ------------------------------------------------------------------ arbitr init

_CONFIG_TEMPLATE: Final = """\
# Arbitr configuration. Relative paths are resolved against this file's folder.
# ARBITR_* environment variables override these settings; see docs/configuration.md.
version: 1
ledger: .arbitr/ledger.db
policy: policy.yaml
key_file: .arbitr/key
lease_ttl: 30s
credentials:
  - env
"""

_POLICY_TEMPLATE: Final = """\
# Arbitr policy. Run 'arbitr policy packs' to list the packs you can include.
version: 1
mode: enforce
include: [{packs}]
rules: []
"""

_IGNORED: Final = frozenset({".arbitr", ".arbitr/", "/.arbitr", "/.arbitr/"})
GitignoreStatus = Literal["added", "present", "missing"]


@dataclass(frozen=True)
class InitResult:
    """What ``init_project`` wrote. Holds paths only, never the key."""

    folder: Path
    config: Path
    policy: Path
    key_file: Path
    ledger: Path
    packs: tuple[str, ...]
    gitignore: GitignoreStatus
    ledger_created: bool


def _check_packs(packs: tuple[str, ...]) -> None:
    from arbitr.policy.packs import PACKS  # noqa: PLC0415 - packs import the policy schema

    for name in packs:
        if name not in PACKS:
            raise ConfigError(f"unknown pack {name!r}; packs: {', '.join(PACKS)}")


def _write_key(path: Path) -> None:
    """A new random 32-byte key as hex, created owner-only (0600 on POSIX)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(secrets.token_hex(MIN_KEY_BYTES) + "\n")


def _ignore_data_dir(folder: Path) -> GitignoreStatus:
    path = folder / ".gitignore"
    if not path.is_file():
        return "missing"
    text = path.read_text(encoding="utf-8")
    if any(line.strip() in _IGNORED for line in text.splitlines()):
        return "present"
    prefix = "" if not text or text.endswith("\n") else "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{prefix}{DATA_DIR}/\n")
    return "added"


def init_project(
    folder: str | Path = ".", *, packs: tuple[str, ...] = (), force: bool = False
) -> InitResult:
    """Write ``arbitr.yaml``, a starter ``policy.yaml`` and a new key, then create the ledger.

    The key file is created owner-only and ``.arbitr/`` is added to an
    existing ``.gitignore``. With ``force`` the three files are replaced (a new
    key is generated) and an existing ledger is kept, never deleted.

    Raises:
        ConfigError: a file exists and ``force`` is not set, or a pack is unknown.
    """
    root = Path(folder).absolute()
    _check_packs(packs)
    targets = (root / CONFIG_FILE, root / POLICY_FILE, root / DATA_DIR / "key")
    existing = [p.name for p in targets if p.exists()]
    if existing and not force:
        raise ConfigError(
            f"{', '.join(existing)} already exist in {root}: run 'arbitr init --force'"
            " to replace them"
        )
    root.mkdir(parents=True, exist_ok=True)
    targets[0].write_text(_CONFIG_TEMPLATE, encoding="utf-8")
    targets[1].write_text(_POLICY_TEMPLATE.format(packs=", ".join(packs)), encoding="utf-8")
    _write_key(targets[2])
    gitignore = _ignore_data_dir(root)
    config = load_config(targets[0], environ={})
    created = not config.ledger.exists()
    config.open_ledger().close()
    return InitResult(
        folder=root,
        config=targets[0],
        policy=config.policy,
        key_file=config.key_file,
        ledger=config.ledger,
        packs=packs,
        gitignore=gitignore,
        ledger_created=created,
    )
