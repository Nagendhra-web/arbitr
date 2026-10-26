"""File previews: a read-only walk of what rm, mv and path arguments would touch."""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

import pytest

from arbitr.preview import DEADLINE
from arbitr.preview.files import CWD, MAX_FILES, PATH_TAGS, preview_files

if TYPE_CHECKING:
    from pathlib import Path


def _tree(root: Path) -> Path:
    data = root / "data"
    (data / "backups" / "2026").mkdir(parents=True)
    (data / "logs").mkdir()
    for i in range(5):
        (data / "logs" / f"app{i}.log").write_bytes(b"x" * 100)
    (data / "backups" / "db.bak").write_bytes(b"y" * 1000)
    (data / "backups" / "2026" / "jan.bak").write_bytes(b"z" * 500)
    (data / "readme.txt").write_bytes(b"hello")
    return data


def _snapshot(root: Path) -> list[tuple[str, int, int]]:
    out = []
    for folder, dirs, files in os.walk(root):
        for name in sorted(dirs + files):
            st = os.stat(os.path.join(folder, name))
            out.append((os.path.join(folder, name), st.st_size, st.st_mtime_ns))
    return sorted(out)


def _posix(path: Path) -> str:
    return path.as_posix()


def test_rm_rf_counts_files_bytes_and_tagged_folders(tmp_path: Path) -> None:
    data = _tree(tmp_path)
    before = _snapshot(tmp_path)
    context = {PATH_TAGS: {"backups": ["**/backups/**"], "logs": ["**/logs/**"]}}
    preview = preview_files({"command": f"rm -rf {_posix(data)}"}, context)
    assert preview.ok, preview
    assert preview.facts["files"] == 8
    assert preview.facts["dirs"] == 4
    assert preview.facts["bytes"] == 500 + 1000 + 500 + 5
    assert preview.facts["files_tagged"] == 7
    assert preview.facts["files_tagged_backups"] == 2
    assert preview.facts["files_tagged_logs"] == 5
    assert (
        preview.summary == "rm would delete 8 files (2.0 KB) in 4 folders, 2 in backups, 5 in logs"
    )
    assert _snapshot(tmp_path) == before


def test_mv_and_path_arguments(tmp_path: Path) -> None:
    data = _tree(tmp_path)
    moved = preview_files({"command": ["mv", _posix(data / "logs"), _posix(tmp_path / "new")]}, {})
    assert moved.ok
    assert moved.facts["files"] == 5
    assert moved.facts["missing"] == 1
    assert moved.summary.startswith("mv would move 5 files")
    plain = preview_files({"path": _posix(data / "readme.txt")}, {})
    assert plain.facts["files"] == 1
    assert plain.facts["dirs"] == 0
    assert plain.summary == "The paths hold 1 file (5 B)"


def test_overlapping_paths_are_counted_once(tmp_path: Path) -> None:
    data = _tree(tmp_path)
    preview = preview_files({"command": f"rm -rf {_posix(data)} {_posix(data / 'logs')}"}, {})
    assert preview.facts["files"] == 8
    assert preview.facts["paths"] == 1


def test_relative_paths_need_a_working_folder(tmp_path: Path) -> None:
    _tree(tmp_path)
    assert not preview_files({"command": "rm -rf ./data"}, {}).ok
    preview = preview_files({"command": "rm -rf ./data/logs"}, {CWD: _posix(tmp_path)})
    assert preview.ok
    assert preview.facts["files"] == 5
    assert not preview_files({"command": "rm -rf data"}, {CWD: "relative/folder"}).ok


@pytest.mark.parametrize("command", ["rm -rf ~/data", "rm -rf $HOME/data", "rm /a/{b,c}"])
def test_paths_that_depend_on_the_environment_fail(command: str) -> None:
    preview = preview_files({"command": command}, {})
    assert not preview.ok
    assert preview.summary.startswith("No preview")


def test_globs_are_expanded_without_a_shell(tmp_path: Path) -> None:
    data = _tree(tmp_path)
    preview = preview_files({"command": f"rm {_posix(data)}/logs/*.log"}, {})
    assert preview.ok
    assert preview.facts["files"] == 5
    nothing = preview_files({"command": f"rm {_posix(data)}/nope/*.log"}, {})
    assert nothing.facts["files"] == 0
    assert nothing.facts["missing"] == 1


def test_no_paths_means_no_preview() -> None:
    preview = preview_files({"command": "echo hi"}, {})
    assert not preview.ok


def test_the_file_limit_stops_the_walk(tmp_path: Path) -> None:
    data = _tree(tmp_path)
    preview = preview_files({"command": f"rm -rf {_posix(data)}"}, {MAX_FILES: 3})
    assert not preview.ok
    assert "would delete at least" in preview.summary
    assert "limit" in preview.summary
    bad = preview_files({"command": f"rm -rf {_posix(data)}"}, {MAX_FILES: "many"})
    assert bad.ok  # the default limit applies


def test_the_deadline_stops_the_walk(tmp_path: Path) -> None:
    data = _tree(tmp_path)
    preview = preview_files({"command": f"rm -rf {_posix(data)}"}, {DEADLINE: time.monotonic() - 1})
    assert not preview.ok
    assert "ran out of time" in preview.summary


def test_links_are_counted_not_followed(tmp_path: Path) -> None:
    data = _tree(tmp_path)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep.txt").write_bytes(b"k")
    try:
        os.symlink(target, data / "link", target_is_directory=True)
    except OSError:
        linked = False  # Windows without the symlink privilege
    else:
        linked = True
    preview = preview_files({"command": f"rm -rf {_posix(data)}"}, {})
    assert preview.facts["files"] == (9 if linked else 8)
    assert (target / "keep.txt").exists()


def test_unreadable_folders_fail_the_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _tree(tmp_path)

    def denied(path: object) -> object:
        raise PermissionError("denied")

    monkeypatch.setattr("arbitr.preview.files.os.scandir", denied)
    preview = preview_files({"command": f"rm -rf {_posix(data)}"}, {})
    assert not preview.ok
    assert "could not be read" in preview.summary


def test_unstattable_paths_fail_the_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(path: object) -> object:
        raise PermissionError("denied")

    monkeypatch.setattr("arbitr.preview.files.os.lstat", denied)
    assert not preview_files({"command": "rm -rf /srv/app"}, {}).ok


def test_bad_tag_settings_are_ignored(tmp_path: Path) -> None:
    data = _tree(tmp_path)
    for tags in ("backups", {"backups": "not-a-list"}, {"x": [5]}):
        preview = preview_files({"command": f"rm -rf {_posix(data)}"}, {PATH_TAGS: tags})
        assert preview.ok
        assert preview.facts["files_tagged"] == 0


def test_drive_paths_match_tags_without_case(tmp_path: Path) -> None:
    data = _tree(tmp_path)
    if _posix(data)[1:2] != ":":
        return  # drive letters exist only on Windows; the POSIX case is covered above
    glob = _posix(data / "Backups").upper() + "/**"
    preview = preview_files({"command": f"rm -rf {_posix(data)}"}, {PATH_TAGS: {"b": [glob]}})
    assert preview.facts["files_tagged_b"] == 2


def test_a_glob_that_expands_past_the_limit_fails(tmp_path: Path) -> None:
    for i in range(30):
        (tmp_path / f"f{i}.log").write_text("x", encoding="utf-8")
    preview = preview_files({"command": f"rm {_posix(tmp_path)}/*.log"}, {MAX_FILES: 10})
    assert not preview.ok
    assert "limit" in preview.summary


def test_tags_match_where_a_link_really_points(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / "db.dump").write_text("x", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.mkdir()
    (alias / "db.dump").write_text("x", encoding="utf-8")
    real = os.path.realpath

    def through_link(path: str) -> str:  # alias stands in for a symlink to backups
        return real(str(path).replace("alias", "backups"))

    monkeypatch.setattr("arbitr.preview.files.os.path.realpath", through_link)
    context = {PATH_TAGS: {"backups": ["**/backups/**"]}}
    preview = preview_files({"command": f"rm -rf {_posix(alias)}"}, context)
    assert preview.ok, preview
    assert preview.facts["files_tagged_backups"] == 1
