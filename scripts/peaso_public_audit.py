#!/usr/bin/env python3
"""Audit publishable Git files using a private, externally maintained deny list."""
import argparse
import json
from pathlib import Path
import subprocess

from peaso.public_audit import check_sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--identifiers', type=Path, required=True, help='Private JSON string array outside this repository')
    args = parser.parse_args()
    root = args.root.resolve()
    if args.identifiers.resolve().is_relative_to(root):
        parser.error('Keep the identifier list outside the public repository')
    names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '--cached', '--others', '--exclude-standard', '-z']).decode().split('\0')
    source = {name: (root / name).read_bytes() for name in set(names) if name and (root / name).is_file()}
    try:
        print(json.dumps(check_sources(source, args.identifiers)))
    except (ValueError, OSError):
        print(json.dumps({'status': 'failed', 'reason': 'private_identifier_or_unreadable_archive'}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
