from __future__ import annotations

import os
from pathlib import Path


def age_tree(path: Path, timestamp: float) -> None:
    """Set descendant mtimes before their parents for deterministic age tests."""
    for current, directories, files in os.walk(path, topdown=False):
        current_path = Path(current)
        for name in files:
            os.utime(current_path / name, (timestamp, timestamp))
        for name in directories:
            os.utime(current_path / name, (timestamp, timestamp))
        os.utime(current_path, (timestamp, timestamp))

