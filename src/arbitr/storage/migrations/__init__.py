"""Versioned, forward-only schema migrations.

Each migration runs once, in order, inside a transaction, and is recorded in
``schema_version``. Migrations are never edited after release; a change is a
new migration.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Migration:
    """One schema step."""

    version: int
    name: str
    sql: str


SQLITE: tuple[Migration, ...] = (
    Migration(
        1,
        "initial ledger schema",
        """
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE runs (
  run_id TEXT PRIMARY KEY,
  principal TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  parent_run_id TEXT REFERENCES runs(run_id),
  scopes TEXT NOT NULL DEFAULT '[]',
  taint TEXT NOT NULL DEFAULT '{}',
  mode TEXT NOT NULL CHECK (mode IN ('enforce', 'shadow')),
  created_at TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE intents (
  intent_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  step_id TEXT,
  tool TEXT NOT NULL,
  args_redacted TEXT NOT NULL,
  intent_hash TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  effect TEXT NOT NULL,
  resources TEXT NOT NULL DEFAULT '[]',
  state TEXT NOT NULL,
  decision TEXT CHECK (decision IN ('allow', 'deny', 'require_approval')),
  decision_rule TEXT,
  decision_reason TEXT,
  shadow_decision TEXT,
  attempt INTEGER NOT NULL DEFAULT 0,
  lease_owner TEXT,
  lease_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX intents_run ON intents(run_id);
CREATE INDEX intents_state ON intents(state);

CREATE TABLE receipts (
  intent_id TEXT PRIMARY KEY REFERENCES intents(intent_id),
  result_hash TEXT NOT NULL,
  result_redacted TEXT,
  external_id TEXT,
  source TEXT NOT NULL CHECK (source IN ('executed', 'probe', 'dedup', 'compensation')),
  created_at TEXT NOT NULL
);

CREATE TABLE approvals (
  approval_id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES intents(intent_id),
  intent_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_by TEXT,
  decided_at TEXT,
  note TEXT
);

CREATE TABLE budget_counters (
  scope_key TEXT PRIMARY KEY,
  value REAL NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  intent_id TEXT,
  run_id TEXT,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE tool_pins (
  server TEXT NOT NULL,
  tool TEXT NOT NULL,
  definition_hash TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  PRIMARY KEY (server, tool)
);
""",
    ),
    Migration(
        2,
        "run scope manifest",
        "ALTER TABLE runs ADD COLUMN scope TEXT",
    ),
    Migration(
        3,
        "execution: exact args flag, schedules, lease and approval indexes",
        """
ALTER TABLE intents ADD COLUMN args_exact INTEGER NOT NULL DEFAULT 0;
ALTER TABLE intents ADD COLUMN scheduled_for TEXT;
CREATE INDEX intents_lease ON intents(state, lease_expires_at);
CREATE INDEX intents_schedule ON intents(state, scheduled_for);
CREATE INDEX approvals_intent ON approvals(intent_id)
""",
    ),
    Migration(
        4,
        "budget reservations per intent",
        """
CREATE TABLE reservations (
  intent_id TEXT NOT NULL REFERENCES intents(intent_id),
  scope_key TEXT NOT NULL,
  amount REAL NOT NULL CHECK (amount > 0),
  PRIMARY KEY (intent_id, scope_key)
)
""",
    ),
)
