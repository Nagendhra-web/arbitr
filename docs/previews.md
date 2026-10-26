# Blast radius previews

A preview measures what an action would affect before it runs, so a human
approver sees what is at stake and policy rules can test real numbers:

- `DELETE would remove 48,212 rows from orders`
- `rm would delete 2,340 files (1.2 GB) in 310 folders, 11 in backups`
- `email to 1,200 recipients, 1,140 external`
- `terraform would destroy 4 resources (1 replaced), 2 critical`
- `3 payments totalling 1,250.00 USD`

Previews only read. They never change a row, a file or a resource.

## When a preview runs

The executor previews an action after it has classified the call and before
the gate decides:

- destructive and financial actions, whenever a built-in previewer fits;
- writes that are SQL changing rows (`DELETE` and `UPDATE`; an `INSERT` is
  not previewed);
- outbound messages that have email recipients;
- any action except a read, when its tool names its own previewer.

Reads are never previewed. A preview runs on every such call, including a
retry with the same idempotency key, so the facts the gate sees are always
fresh. When an action needs approval, its preview is shown on the approval
card; a preview that failed or timed out is marked there in capitals, and the
stricter decision was applied.

A tool can name its own previewer with `ToolSpec.preview`, written
`package.module:function` like `resource_extractor`. When it names none, a
built-in previewer is chosen from the resources the extractors found, first
match wins:

| Resources found | Previewer | Facts |
| --- | --- | --- |
| a table (SQL) | `arbitr.preview.sql:preview_sql` | `rows_affected`, `tables`, `table` |
| a path (shell command or path argument) | `arbitr.preview.files:preview_files` | `files`, `dirs`, `bytes`, `paths`, `missing`, `files_tagged`, `files_tagged_<tag>` |
| an email recipient | `arbitr.preview.email:preview_email` | `recipients`, `external_recipients`, `internal_recipients`, `domains` |
| none of these, financial effect | `arbitr.preview.payments:preview_payments` | `amount_total`, `payments`, `currency` |

Terraform plans have no resource kind of their own, so a terraform tool names
`arbitr.preview.terraform:preview_terraform` (facts `resources_destroyed`,
`resources_replaced`, `resources_created`, `resources_updated`, `critical`).

Note that the SQL extractor classifies `DELETE ... WHERE` and `UPDATE ...
WHERE` as writes. To preview them, register the tool with
`effect="destructive"`; the effect is never lowered, so the gate then sees a
destructive action with a row count.

## Configuring previews

```python
import sqlite3
from arbitr.executor import Ledger


def read_only() -> sqlite3.Connection:
    return sqlite3.connect("file:shop.db?mode=ro", uri=True)


ledger = Ledger.open(
    "ledger.db",
    policy,
    key=key,
    preview_context={
        "sql_connection": read_only,
        "sql_dialect": "sqlite",
        "path_tags": {"backups": ["/srv/**/backups/**"]},
        "cwd": "/srv/app",
        "max_files": 100_000,
        "internal_domains": ["corp.example"],
        "critical_tags": ["critical", "env=prod"],
    },
    preview_timeout=2.0,
)
```

| Key | Used by | Meaning |
| --- | --- | --- |
| `sql_connection` | SQL | A read-only DB-API connection, or a function that returns one. A function is better: the preview runs in a worker thread and closes the connection it made. |
| `sql_dialect` | SQL | The `sqlglot` dialect name. The generic dialect when absent. |
| `path_tags` | files | Tag names mapped to path globs. Files under them are counted per tag. |
| `cwd` | files | An absolute folder that relative paths are resolved against. |
| `max_files` | files | The most entries the walk visits (default 100,000). |
| `internal_domains` | email | Domains (and their subdomains) that count as internal. |
| `terraform_plan` | terraform | The `terraform show -json` output, when the call does not carry it. |
| `critical_tags` | terraform | `key` matches any value of that tag, `key=value` only that value. |

Give the SQL previewer a connection that cannot write: SQLite opened with
`mode=ro`, or a database user that may only `SELECT`. The previewer only runs
a `SELECT COUNT(*)` it built itself, but a read-only connection also protects
against functions with side effects inside a `WHERE` clause.

Every previewer gets `deadline` in its context, a `time.monotonic()` value.
Custom previewers that loop should stop once it has passed.

## What each previewer does

**SQL.** The statement is parsed with `sqlglot` (the `sql` extra) and
rewritten to `SELECT COUNT(*) FROM <table> WHERE <the same condition>`. A
statement without `WHERE` counts the whole table. `DROP TABLE` and `TRUNCATE`
count every table they name. Anything it cannot rewrite safely fails the
preview instead of guessing: more than one statement, joins (`USING`,
`UPDATE ... FROM`), `LIMIT`, `RETURNING`, common table expressions, bound
parameters, and other statement kinds. On SQLite a query still running at the
deadline is interrupted.

**Files.** Paths come from the shell extractor (`rm`, `rm -rf`, `mv`,
`find -delete` and the other commands it knows) and from arguments named like
paths. Each path is walked with `os.scandir` and `os.lstat`. Symbolic links
and junctions count as one entry and are never followed. Globs are expanded
without a shell; brace expansion, `~` and `$VAR` fail the preview, and so does
a relative path when no `cwd` is set. The walk stops at `max_files` or the
deadline; the preview then fails and its counts are a lower bound.

**Terraform.** Reads the plan JSON from `plan_json`, `terraform_plan` or
`plan` in the arguments (an object or text), or from the context. Terraform is
never run. A change whose actions include `delete` counts as destroyed; with
`create` too it also counts as replaced. A destroyed resource is critical when
its current `tags`, `tags_all` or `labels` match `critical_tags`.

**Email.** Recipients come from the email extractor (`to`, `cc`, `bcc`,
`recipients` and similar), each counted once. A recipient that cannot be
parsed fails the preview.

**Payments.** Every value under a key named `amount`, at any depth, is
totalled and counted. A value that is not a finite, non-negative number, or
amounts in more than one currency, fail the preview.

## Rules on preview facts

`when.preview` takes a list of conditions with the same operators as
`when.args`, applied to the preview facts:

```yaml
rules:
  - id: big-delete
    when:
      tool: db.exec
      preview: [{ path: "$.rows_affected", op: gt, value: 1000 }]
    then: require_approval
    reason: Deleting more than 1000 rows needs a human.
  - id: backups
    when:
      tool: shell.run
      preview: [{ path: "$.files_tagged_backups", op: gt, value: 0 }]
    then: deny
    reason: Agents never touch backups.
```

When an action was not previewed (another effect, or no previewer fits), its
facts are empty, so these conditions do not hold. `{path: "$.rows_affected",
op: exists, value: false}` matches exactly that case.

Policy test cases accept `preview: {rows_affected: 5000}` and
`preview_ok: false`, so rules on preview facts can be tested like any other.

## When a preview fails

A preview fails (`ok` is false) when it times out, raises, cannot measure the
action without guessing, or is cut short. Its facts are then not trusted.

The rule: **a failed preview can only make a decision stricter.** The gate
decides twice, once as if every rule with a preview condition matched and
once as if none did, and keeps the stricter decision. The other conditions of
those rules still have to hold. So:

- a `deny` or `require_approval` rule on preview facts applies;
- an `allow` or `delay` rule on preview facts cannot replace a stricter
  default (destructive actions need approval by default);
- rules without preview conditions are not affected.

`Decision.preview_assumed` is true when this happened, and `explain()` says so.

## Where an approver finds the preview

The preview is recorded as a `preview` event in the audit chain, in the same
transaction as the decision, after going through the ledger's redactor.
`Ledger.preview_of(intent_id)` returns the latest one as a `Preview`, or None
when the action was not previewed. Because the event is part of the chain,
`verify` covers it like any other record.

## Safety rules for previewers

- SQL counts run read-only: on SQLite with `PRAGMA query_only` (restored
  afterwards), on other databases inside `SET TRANSACTION READ ONLY`, always
  rolled back. For databases other than SQLite, give the preview a
  connection factory, not a shared connection: the rollback would throw away
  someone else's work in progress.
- Statements with comments, and WHERE clauses that call a function the
  parser does not know, are not previewed: the database could read them
  differently. The preview fails, so preview rules take the stricter path.
- File previews expand globs lazily under the same entry limit and time
  limit as the walk, and match folder tags both where a path is written and
  where it really points, so a symlink into a tagged folder still counts.
- Errors are recorded by type only; their text can carry data the previewer
  read.
- Which SQL counts as changing rows fails closed: only plain reads (`SELECT`
  without `INTO`) and plain `INSERT`s do not. Upserts, `REPLACE`, `CALL`,
  statements the parser does not recognize and text that does not parse are
  all previewed, and fail the preview when they cannot be counted.
- On databases other than SQLite the preview asks the database to confirm
  the transaction is read-only (`SHOW transaction_read_only`, or
  `SELECT @@transaction_read_only`) and refuses to count if it cannot.

