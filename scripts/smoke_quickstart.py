"""Smoke test run against the installed wheel in a fresh virtualenv.

Grows into the README quickstart (a blocked DROP TABLE on prod) once the
decorator exists.
"""

from __future__ import annotations

import importlib.resources
import subprocess
import sys
from pathlib import Path

import arbitr


def main() -> int:
    assert arbitr.__version__ != "0.0.0+unknown", "package metadata missing"
    assert importlib.resources.files("arbitr").joinpath("py.typed").is_file(), "py.typed missing"
    # The core install must not pull in the CLI extra, and must say so politely.
    exe = Path(sys.executable).parent / ("arbitr.exe" if sys.platform == "win32" else "arbitr")
    proc = subprocess.run([str(exe), "--help"], capture_output=True, text=True, check=False)
    assert proc.returncode == 1, proc
    assert 'pip install "arbitr[cli]"' in proc.stderr, proc.stderr
    print(f"quickstart smoke ok: arbitr {arbitr.__version__}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
