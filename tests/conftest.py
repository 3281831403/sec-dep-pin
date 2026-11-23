"""Pytest bootstrap for the src layout.

The exercise is intentionally not installed. Put src on sys.path so the
tests import the package exactly as a checkout would.
"""

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))