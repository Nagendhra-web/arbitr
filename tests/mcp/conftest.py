"""The MCP proxy tests import their helpers (fake_upstream, harness) as plain modules."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
