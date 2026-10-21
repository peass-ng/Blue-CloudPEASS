"""Run one complete, deterministic file shard of the ordinary pytest suite.

Pytest still receives ``tests`` as its collection root.  Ignoring the other
shards' files avoids importing them on every xdist worker, while preserving the
full-suite draft isolation and source-admission hooks in tests/conftest.py.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


TESTS = Path("tests")


def test_files() -> list[Path]:
    return sorted(
        path for path in TESTS.rglob("*.py")
        if path.name.startswith("test_") or path.name.endswith("_test.py")
    )


def partition(files: list[Path], count: int) -> list[list[Path]]:
    if count < 1 or count > len(files):
        raise ValueError("shard count must be between 1 and the number of test files")
    shards: list[list[Path]] = [[] for _ in range(count)]
    weights = [0] * count
    # Largest files first limits skew from heavily parametrized modules without
    # executing or importing any test during scheduling. Ties are stable.
    for path in sorted(files, key=lambda file: (-file.stat().st_size, str(file))):
        index = min(range(count), key=lambda shard: (weights[shard], shard))
        shards[index].append(path)
        weights[index] += path.stat().st_size
    return [sorted(shard) for shard in shards]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--verify", action="store_true", help="check coverage and print shard sizes without pytest")
    args, pytest_args = parser.parse_known_args()
    if pytest_args and pytest_args[0] == "--":
        pytest_args.pop(0)
    files = test_files()
    if not files or not 0 <= args.shard < args.shards:
        parser.error("invalid shard or no test files")
    shards = partition(files, args.shards)
    if sorted(path for shard in shards for path in shard) != files:
        raise RuntimeError("test shard coverage is incomplete or duplicated")
    print(
        f"shard {args.shard + 1}/{args.shards}: {len(shards[args.shard])}/{len(files)} "
        f"test files, {sum(path.stat().st_size for path in shards[args.shard])} source bytes",
        flush=True,
    )
    if args.verify:
        return 0
    if not pytest_args:
        parser.error("pass pytest options after --")
    selected = set(shards[args.shard])
    ignored = [f"--ignore={path}" for path in files if path not in selected]
    command = [sys.executable, "-m", "pytest", *pytest_args, *ignored, str(TESTS)]
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
