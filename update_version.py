#!/usr/bin/env python3
"""Update version number based on current timestamp"""

from datetime import datetime
from pathlib import Path

VERSION_FILE = Path(__file__).parent / "VERSION"

now = datetime.now()
version = f"v{now.year}.{now.month}.{now.day}.{now.hour:02d}_{now.minute:02d}"

with open(VERSION_FILE, "w") as f:
    f.write(version + "\n")

print(f"Updated version to: {version}")
