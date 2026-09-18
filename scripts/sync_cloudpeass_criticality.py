#!/usr/bin/env python3
"""Sync CloudPEASS sensitive-permission combinations into Blue-CloudPEASS."""

from __future__ import annotations

import argparse
import ast
import hashlib
import os
import subprocess
from pathlib import Path

import yaml


PROVIDERS = ("aws", "gcp", "azure")
SOURCE_VARIABLES = {
    "critical": "very_sensitive_combinations",
    "high": "sensitive_combinations",
}


def _read_source_lists(path: Path) -> dict[str, list[list[str]]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assignments: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in SOURCE_VARIABLES.values():
            assignments[target.id] = ast.literal_eval(node.value)

    missing = set(SOURCE_VARIABLES.values()) - assignments.keys()
    if missing:
        raise ValueError(f"Missing variables in {path}: {', '.join(sorted(missing))}")

    result: dict[str, list[list[str]]] = {}
    for level, variable in SOURCE_VARIABLES.items():
        raw_combinations = assignments[variable]
        if not isinstance(raw_combinations, list):
            raise ValueError(f"{variable} in {path} is not a list")
        combinations: list[list[str]] = []
        for raw_combination in raw_combinations:
            if not isinstance(raw_combination, list) or not raw_combination:
                raise ValueError(f"Invalid combination in {path}: {raw_combination!r}")
            if not all(isinstance(permission, str) and permission for permission in raw_combination):
                raise ValueError(f"Invalid permission in {path}: {raw_combination!r}")
            combinations.append(raw_combination)
        result[level] = combinations
    return result


def _source_revision(source_root: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        text=True,
    ).strip()


def _render(provider: str, source_root: Path, revision: str) -> str:
    relative_source = Path("src") / "sensitive_permissions" / f"{provider}.py"
    source_path = source_root / relative_source
    combinations = _read_source_lists(source_path)
    data = {
        "version": 1,
        "provider": provider,
        "source_repository": "carlospolop/CloudPEASS",
        "source_revision": revision,
        "source_path": relative_source.as_posix(),
        "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        **combinations,
    }
    header = "# Synced from CloudPEASS. Run scripts/sync_cloudpeass_criticality.py to refresh.\n"
    return header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=1000)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cloudpeass-root",
        type=Path,
        default=Path(os.environ.get("CLOUDPEASS_ROOT", "../CloudPEASS")),
        help="CloudPEASS checkout root (default: CLOUDPEASS_ROOT or ../CloudPEASS)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the checked-in lists differ; do not write files.",
    )
    args = parser.parse_args()

    source_root = args.cloudpeass_root.expanduser().resolve()
    source_dir = source_root / "src" / "sensitive_permissions"
    if not source_dir.is_dir():
        parser.error(f"CloudPEASS sensitive-permission directory not found: {source_dir}")

    target_dir = Path(__file__).resolve().parents[1] / "risk_rules"
    revision = _source_revision(source_root)
    drifted: list[Path] = []
    for provider in PROVIDERS:
        target_path = target_dir / f"{provider}_criticality.yaml"
        expected = _render(provider, source_root, revision)
        current = target_path.read_text(encoding="utf-8") if target_path.exists() else None
        if current == expected:
            continue
        drifted.append(target_path)
        if not args.check:
            target_path.write_text(expected, encoding="utf-8")

    if args.check and drifted:
        print("CloudPEASS criticality lists are out of sync:")
        for path in drifted:
            print(f"  {path}")
        return 1
    if drifted:
        print(f"Updated {len(drifted)} criticality list(s).")
    else:
        print("CloudPEASS criticality lists are in sync.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
