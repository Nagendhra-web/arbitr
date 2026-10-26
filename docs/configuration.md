# Configuration

Arbitr reads one config file, `arbitr.yaml`, plus `ARBITR_*` environment
variables. `arbitr init` writes a working setup and `arbitr config check`
validates it without running anything.

## Getting started

```bash
pip install "arbitr[cli]"
arbitr init --packs databases,git
arbitr config check
```

`arbitr init` writes these files into the current folder (or `--dir PATH`):

| File | What it is |
| --- | --- |
| `arbitr.yaml` | The config file. |
| `policy.yaml` | A starter policy in enforce mode that includes the packs you named. |
| `.arbitr/key` | A new random 32-byte ledger key, as hex, readable by the owner only (0600 on POSIX). |
| `.arbitr/ledger.db` | The SQLite ledger. |

If the folder has a `.gitignore`, `init` adds `.arbitr/` to it. If it has
none, `init` tells you to keep `.arbitr/` out of version control, because it
holds the key.

`init` refuses to overwrite `arbitr.yaml`, `policy.yaml` or the key. With
`--force` it replaces all three and generates a new key. An existing ledger is
kept, never deleted.

From Python:

```python
from arbitr.config import load_config

config = load_config()  # or load_config("path/to/arbitr.yaml")
with config.open_ledger() as ledger:
    ...
```

## The config file

Every field except `version` is optional.

```yaml
version: 1
ledger: .arbitr/ledger.db
policy: policy.yaml
key_file: .arbitr/key
worker_id: worker-1
lease_ttl: 30s
approval_ttl: 15m
credentials:
  - env
  - file: secrets
  - keyring: arbitr
approvals:
  webhook_url: https://hooks.example.com/arbitr
  link_base_url: https://arbitr.example.com
  approvers:
    bob: [finance]
    carol: []
```

| Field | Default | Meaning |
| --- | --- | --- |
| `version` | required | Always `1`. |
| `ledger` | `.arbitr/ledger.db` | The SQLite ledger file. |
| `policy` | `policy.yaml` | The policy file. |
| `key_file` | `.arbitr/key` | The ledger HMAC key as hex. Used when `ARBITR_LEDGER_KEY` is not set. |
| `worker_id` | host name plus a random suffix | Names this process in leases. |
| `lease_ttl` | `30s` | How long a running action's lease lasts before recovery may take it over. |
| `approval_ttl` | the policy's `approval.expires_after` | How long an approval request stays open. Set it here only to override the policy. |
| `credentials` | `[env]` | Where tools' credentials come from, tried in order. An empty list means none. |
| `approvals.webhook_url` | none | An http or https URL. Each new approval request is POSTed there as JSON with a readable card. It needs `link_base_url`. |
| `approvals.link_base_url` | none | The base URL for the signed approve and reject links in each notice. |
| `approvals.approvers` | none | Approver names and their roles. Each gets their own signed links. |

Durations are a number of seconds or a number with `s`, `m`, `h` or `d`.

Relative paths in the file are resolved against the file's folder, not the
working folder, so the config works from anywhere.

Unknown fields are errors. Every error names the file and the field, for
example `invalid config file /srv/app/arbitr.yaml: lease_ttl: must be more
than zero`.

## Credential providers

Tools that declare credentials get them only after the gate allows the
action. The agent never sees them.

| Entry | Reads from |
| --- | --- |
| `env` | `ARBITR_CRED_<NAME>` environment variables. Dots and dashes in the name become underscores. |
| `file: <folder>` | One file per credential, named after it. On POSIX a file readable by other users is refused. |
| `keyring: <service>` | The OS keyring entry with that service and the credential name as the user name. Needs `pip install "arbitr[keyring]"`. |

## Environment variables

| Variable | Replaces |
| --- | --- |
| `ARBITR_CONFIG` | The path of the config file. |
| `ARBITR_LEDGER` | `ledger` |
| `ARBITR_POLICY` | `policy` |
| `ARBITR_KEY_FILE` | `key_file` |
| `ARBITR_LEDGER_KEY` | The key itself, as hex. Used instead of the key file. |

Relative paths in environment variables are resolved against the working
folder. An empty variable counts as unset.

## Precedence

For each setting: environment over file over defaults.

The config file itself is found in this order:

1. `--config PATH` on the command line (or the `path` given to `load_config`),
2. `ARBITR_CONFIG`,
3. `arbitr.yaml` in the working folder.

A missing config file is an error; there is no silent fallback.

## The ledger key

The key is the HMAC key for redaction markers in the ledger. It must be at
least 32 bytes (64 hex characters). It comes from `ARBITR_LEDGER_KEY` or the
key file, never from the config file: a `ledger_key` field in `arbitr.yaml`
is refused.

On POSIX systems a key file that group or others can read is refused. Fix it
with `chmod 600 .arbitr/key`.

Arbitr never prints, logs or stores the key or any credential value. Error
messages name the variable or file, not its content.

## arbitr config check

```bash
arbitr config check [--config PATH] [--json]
```

Checks, without running any action:

- the config file loads and every field is valid,
- the policy file loads,
- the key is readable, valid hex, long enough and not shared with other users,
- every `file` credential folder exists, and the keyring package is installed
  when a `keyring` provider is listed,
- the ledger exists, opens and its audit chain verifies.

It does not create a missing ledger and never reads credential values. It
exits 0 when everything is usable and 1 with the problems listed otherwise.
`--json` prints one object:

```json
{"config": "/srv/app/arbitr.yaml", "ledger": "/srv/app/.arbitr/ledger.db", "ok": true, "policy": "/srv/app/policy.yaml", "problems": []}
```

## Who may approve

`approvals.approvers` lists the people who may approve and the roles each
holds. The command line takes roles from there, never from the person
running it: `arbitr approvals approve <id> --as bob` acts with bob's
configured roles, and a name that is not listed is refused. Without the
list, only approvals that anyone may give alone can be decided from the
command line; a two-person rule or a role needs the list.

## Keep agents apart from Arbitr

Arbitr refuses any agent action that runs the `arbitr` command line (or
`python -m arbitr`), or that names the `.arbitr` folder, the ledger, the key
file, the policy or this config. The refusal holds in every mode, including
shadow mode, under the rule `arbitr-self-protection`.

That check reads the text of each action, so an agent that can run arbitrary
code could still hide what it does. The real protection is the operating
system: run your agents as a user that cannot read the key file and cannot
write the ledger, the policy or this config. Give approvers their own
accounts.

