"""Write the machine-readable CI record.

Called by scripts/ci.sh at the end of every run. Stages arrive as tab-separated
lines: name, result, seconds, note.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path


def parse_stages(tsv: str) -> list[dict[str, object]]:
    stages: list[dict[str, object]] = []
    for line in tsv.splitlines():
        if not line.strip():
            continue
        name, result, seconds, note = [*line.split("\t"), "", "", "", ""][:4]
        if result not in {"PASS", "FAIL", "PENDING"}:
            raise ValueError(f"bad stage result {result!r} for {name!r}")
        stages.append({"name": name, "result": result, "seconds": int(seconds), "note": note})
    return stages


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Write a CI record.")
    p.add_argument("path")
    p.add_argument("--sha", required=True)
    p.add_argument("--mode", choices=["fast", "full"], required=True)
    p.add_argument("--result", choices=["pass", "fail"], required=True)
    p.add_argument("--tree-clean", choices=["true", "false"], required=True)
    p.add_argument("--in-container", choices=["true", "false"], required=True)
    p.add_argument("--started", required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--image-digest", default="")
    p.add_argument("--stages", default="")
    a = p.parse_args(argv)

    stages = parse_stages(a.stages)
    if a.result == "pass" and any(s["result"] == "FAIL" for s in stages):
        raise ValueError("a run with a FAIL stage cannot be recorded as pass")
    record = {
        "sha": a.sha,
        "mode": a.mode,
        "result": a.result,
        "tree_clean": a.tree_clean == "true",
        "in_container": a.in_container == "true",
        "started_at": a.started,
        "finished_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "os": f"{platform.system()} {platform.release()} {platform.machine()}",
        "python": platform.python_version(),
        "ci_image_digest": a.image_digest,
        "log": a.log,
        "stages": stages,
    }
    path = Path(a.path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
