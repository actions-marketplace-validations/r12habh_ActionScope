#!/usr/bin/env python3
"""
Bump ActionScope version across all files.
Usage: python scripts/bump_version.py 0.1.0 0.2.0
"""

from __future__ import annotations

import sys
from pathlib import Path


def bump_version(old: str, new: str) -> None:
    files_to_update = [
        "pyproject.toml",
        "actionscope/__init__.py",
        "action.yml",
    ]

    for filepath in files_to_update:
        path = Path(filepath)
        content = path.read_text()
        updated = content.replace(old, new)
        if content != updated:
            path.write_text(updated)
            print(f"Updated {filepath}: {old} -> {new}")
        else:
            print(f"No change in {filepath}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scripts/bump_version.py OLD_VERSION NEW_VERSION")
        sys.exit(1)
    bump_version(sys.argv[1], sys.argv[2])
