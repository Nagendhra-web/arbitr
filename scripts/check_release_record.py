"""Check that a CI record proves a release-ready commit.

    python scripts/check_release_record.py <sha>

The record must be ci-logs/<sha>.docker.json from `make ci-docker`: full mode,
result pass, clean tree, run in the container, for exactly this sha.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def problems(record: dict[str, object], sha: str) -> list[str]:
    """Return every reason the record is not release proof (empty means it is)."""
    expected = {
        "sha": sha,
        "mode": "full",
        "result": "pass",
        "tree_clean": True,
        "in_container": True,
    }
    found = [
        f"{key} is {record.get(key)!r}, expected {want!r}"
        for key, want in expected.items()
        if record.get(key) != want
    ]
    stages = record.get("stages")
    if not isinstance(stages, list) or not stages:
        found.append("the record lists no stages")
    elif any(isinstance(s, dict) and s.get("result") == "FAIL" for s in stages):
        found.append("a stage failed")
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check_release_record.py <sha>", file=sys.stderr)
        return 2
    sha = argv[0]
    path = Path("ci-logs") / f"{sha}.docker.json"
    if not path.is_file():
        print(f"no make ci-docker record for {sha} ({path})", file=sys.stderr)
        return 1
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return 1
    found = problems(record, sha) if isinstance(record, dict) else ["not a JSON object"]
    for p in found:
        print(f"{path}: {p}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
