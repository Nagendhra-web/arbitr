"""Fuzz: secrets written through the ledger never appear in the database files.

Plants secrets in every place a caller can put data: free text, named fields,
JSON inside a string, URLs, resource references, run metadata, decision
reasons and transition details, as strings and as integers. Then reads the raw
bytes of the SQLite file, its WAL and shared memory, so a secret in any table,
index or free page is caught.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from arbitr.core.intent import build_intent
from arbitr.core.redact import Redactor
from arbitr.core.spec import ResourceRef, ToolSpec
from arbitr.core.states import IntentState
from arbitr.storage.sqlite import SQLiteStorage

SPEC = ToolSpec(name="email.send", effect="external_comm", redact=["$.card_ref"])

# Each shape turns a random token into a secret. The token is part of every
# secret, so "the secret is absent" also means "the token is not exposed".
TEXT_SHAPES = [
    lambda s: "AKIA" + s.upper().ljust(16, "Q")[:16],
    lambda s: "ghp_" + (s * 40)[:36],
    lambda s: "sk-ant-api03-" + (s * 30)[:30],
    lambda s: "xoxb-" + (s * 12)[:12],
    lambda s: "Bearer " + (s * 20)[:20],
    lambda s: "Basic " + (s * 4)[:16] + "==",
]
CARDS_STR = ["4111 1111 1111 1111", "5500-0000-0000-0004", "378282246310005"]
CARD_INTS = [4111111111111111, 5500000000000004, 378282246310005]
token = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=6, max_size=12)


def raw_bytes(path: Path) -> bytes:
    data = b""
    for suffix in ("", "-wal", "-shm"):
        f = Path(str(path) + suffix)
        if f.exists():
            data += f.read_bytes()
    return data


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    shape=st.sampled_from(range(len(TEXT_SHAPES))),
    tok=token,
    pw_token=token,
    card=st.sampled_from(range(len(CARDS_STR))),
    where=st.integers(0, 9),
)
def test_no_secret_reaches_the_database_files(
    shape: int, tok: str, pw_token: str, card: int, where: int
) -> None:
    secret = TEXT_SHAPES[shape](tok)
    password = f"Zq7pw-{pw_token}"  # distinctive, cannot match schema text
    card_str, card_int = CARDS_STR[card], CARD_INTS[card]
    args: dict[str, object] = {
        0: {"body": f"hi {secret}", "password": password},
        1: {"headers": {secret: "x"}, "Authorization": password},
        2: {"payload": '{"password": "' + password + '", "user": "ann"}', "note": secret},
        3: {"nested": [[{"k": secret}]], "db_password": password},
        4: {"card": card_int, "memo": f"card {card_str}", "token": password, "s": secret},
        5: {"url": f"postgres://admin:{password}@prod/db", "s": secret},
        6: {"card_ref": password, "other": secret},
        7: {"client_secret": password, "list": [card_int, secret]},
        8: {"accessToken": password, "nested": {"clientSecret": password}, "s": secret},
        9: {"DBPassword": password, "sessionToken": password, "x": [secret]},
    }[where]
    resource = ResourceRef(
        kind="database",
        uri=f"https://user:{password}@example.com/x",
        attrs={"api_key": password, "note": secret},
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ledger.db"
        db = SQLiteStorage.open(path, Redactor(b"fuzz-db-key-" * 3))
        with db.transaction() as tx:
            tx.insert_run("r", "alice", "bot", metadata={"note": secret, "password": password})
        intent = build_intent(SPEC, args, run_id="r", principal="alice", resources=(resource,))
        with db.transaction() as tx:
            tx.insert_intent(intent)
            tx.transition(
                intent.intent_id,
                IntentState.DENIED,
                expected=IntentState.PROPOSED,
                fields={"decision": "deny", "decision_reason": f"found {secret} in the call"},
                detail={"why": f"saw {secret}", "card": card_int},
            )
            tx.append_event("note", {"echo": secret, "pw": password, "card": card_str})
        db.close()
        stored = raw_bytes(path)
    assert secret.encode() not in stored
    assert password.encode() not in stored
    assert str(card_int).encode() not in stored
    assert card_str.encode() not in stored
