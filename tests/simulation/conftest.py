import sys
from pathlib import Path

# The simulation modules are plain scripts (run.py is also a CLI), so make them importable.
sys.path.insert(0, str(Path(__file__).parent))
