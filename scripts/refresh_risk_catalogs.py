#!/usr/bin/env python3
"""Reclassify existing catalogs and add audited exact permissions, entirely offline."""
from __future__ import annotations

import argparse
from pathlib import Path
import yaml

try:
    from .permission_risk_classifier import classify_permission
    from .cloud_permission_risks import _load_yaml, is_non_permission
except ImportError:
    from permission_risk_classifier import classify_permission
    from cloud_permission_risks import _load_yaml, is_non_permission


def refresh(root: Path, *, check: bool = False) -> None:
    stale = []
    for provider in ('aws', 'gcp', 'azure'):
        path = root / f'{provider}_permissions_cat.yaml'
        original = yaml.safe_load(path.read_text())
        permissions = {p for values in original.values() for p in values}
        permissions.update(_load_yaml(provider).get('severity_overrides', {}))
        categories = {level: [] for level in ('low', 'medium', 'high', 'critical')}
        for permission in sorted(p for p in permissions if not is_non_permission(provider, p)):
            categories[classify_permission(provider, permission, unknown_default='medium')].append(permission)
        expected = yaml.safe_dump(categories, sort_keys=False, width=120)
        if check:
            if path.read_text() != expected:
                stale.append(path.name)
        else:
            path.write_text(expected)
    if stale:
        raise SystemExit('Stale categorized catalogs: ' + ', '.join(stale))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    refresh(Path(__file__).resolve().parent.parent, check=args.check)


if __name__ == '__main__':
    main()
