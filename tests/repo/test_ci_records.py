"""Tests for the CI record writer and the release record check."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from shellutil import SCRIPTS


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


writer = load("write_ci_record")
checker = load("check_release_record")

STAGES = "Deps\tPASS\t1\t\nBench\tPENDING\t0\tlater\n"


def write(tmp_path: Path, **overrides: str) -> dict[str, object]:
    args = {
        "--sha": "abc",
        "--mode": "full",
        "--result": "pass",
        "--tree-clean": "true",
        "--in-container": "true",
        "--started": "2026-10-24T00:00:00Z",
        "--log": "ci-logs/x.log",
        "--stages": STAGES,
    }
    args.update(overrides)
    out = tmp_path / "rec.json"
    argv = [str(out)] + [x for kv in args.items() for x in kv]
    assert writer.main(argv) == 0
    data: dict[str, object] = json.loads(out.read_text(encoding="utf-8"))
    return data


def test_writer_records_types_and_stages(tmp_path: Path) -> None:
    rec = write(tmp_path)
    assert rec["tree_clean"] is True
    assert rec["in_container"] is True
    assert rec["stages"] == [
        {"name": "Deps", "result": "PASS", "seconds": 1, "note": ""},
        {"name": "Bench", "result": "PENDING", "seconds": 0, "note": "later"},
    ]


def test_writer_refuses_pass_with_a_failed_stage(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot be recorded as pass"):
        write(tmp_path, **{"--stages": "Deps\tFAIL\t1\t\n"})


def test_writer_rejects_unknown_stage_result(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="bad stage result"):
        write(tmp_path, **{"--stages": "Deps\tSKIPPED\t1\t\n"})


def test_valid_docker_record_is_release_proof(tmp_path: Path) -> None:
    assert checker.problems(write(tmp_path), "abc") == []


@pytest.mark.parametrize(
    ("override", "problem"),
    [
        ({"--mode": "fast"}, "mode"),
        ({"--result": "fail", "--stages": "Deps\tFAIL\t1\t\n"}, "result"),
        ({"--tree-clean": "false"}, "tree_clean"),
        ({"--in-container": "false"}, "in_container"),
        ({"--sha": "other"}, "sha"),
        ({"--stages": ""}, "no stages"),
    ],
)
def test_release_check_rejects(tmp_path: Path, override: dict[str, str], problem: str) -> None:
    found = checker.problems(write(tmp_path, **override), "abc")
    assert any(problem in p for p in found), found


def test_release_check_needs_the_docker_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ci-logs").mkdir()
    assert checker.main(["abc"]) == 1
    (tmp_path / "ci-logs" / "abc.docker.json").write_text("{not json", encoding="utf-8")
    assert checker.main(["abc"]) == 1
    (tmp_path / "ci-logs" / "abc.docker.json").write_text(
        json.dumps(write(tmp_path)), encoding="utf-8"
    )
    assert checker.main(["abc"]) == 0
