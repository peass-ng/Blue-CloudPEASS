"""Build-time proof that the non-root worker can read every bundled source file."""

from __future__ import annotations

import os
from pathlib import Path


EXPECTED_ID = 10001
ROOT = Path("/app")
INPUTS = ("pyproject.toml", "peaso", "bluepeass", "scripts", "risk_rules")


def _read_file(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Bundled source contains a symlink: {path}")
    with path.open("rb") as source:
        source.read(1)


def _raise_walk_error(error: OSError) -> None:
    raise error


def verify(root: Path = ROOT) -> int:
    if (os.getuid(), os.getgid()) != (EXPECTED_ID, EXPECTED_ID):
        raise RuntimeError("Bundled source check must run as UID/GID 10001")

    count = 0
    for name in INPUTS:
        entry = root / name
        if entry.is_symlink() or not entry.exists():
            raise RuntimeError(f"Missing or linked bundled input: {name}")
        if entry.is_file():
            _read_file(entry)
            count += 1
            continue
        if not entry.is_dir():
            raise RuntimeError(f"Unsupported bundled input type: {name}")
        for current, directories, files in os.walk(entry, onerror=_raise_walk_error):
            directory = Path(current)
            if not os.access(directory, os.R_OK | os.X_OK):
                raise PermissionError(f"Cannot traverse bundled directory: {directory}")
            for child in directories:
                if (directory / child).is_symlink():
                    raise RuntimeError(f"Bundled source contains a symlink: {directory / child}")
            for child in files:
                _read_file(directory / child)
                count += 1

    if count == 0:
        raise RuntimeError("No bundled runtime files were checked")
    return count


if __name__ == "__main__":
    print(f"Verified readability of {verify()} bundled runtime files")
