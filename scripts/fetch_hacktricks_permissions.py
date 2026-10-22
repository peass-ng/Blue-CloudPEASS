#!/usr/bin/env python3
"""Fetch one consistent revision of HackTricks permission data with bounded retries.

With --with-privesc the same sparse checkout also contains the privilege-escalation path
catalog (src/privilege-escalation-paths-cspm-reviewed) and the pentesting-cloud pages its `source` fields
point to. --revision-file pins that checkout to the reviewed Cloud commit.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

SOURCE_URL = 'https://github.com/HackTricks-wiki/hacktricks-cloud.git'
ATTEMPTS = 5
ATTEMPT_TIMEOUT = 150
BACKOFF_SECONDS = (15, 30, 60, 120)
PERMISSIONS_PATH = 'src/permission-categorizations'
PRIVESC_PATHS = ('src/privilege-escalation-paths-cspm-reviewed', 'src/pentesting-cloud')
REVISION_RE = re.compile(r'[0-9a-f]{40}\Z')


def _git(arguments, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(['git', *arguments], ATTEMPT_TIMEOUT)
    return subprocess.run(
        ['git', '-c', 'http.lowSpeedLimit=1024', '-c', 'http.lowSpeedTime=30', *arguments],
        check=True, timeout=remaining, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
    )


def fetch(destination: Path, *, with_privesc=False, require_privesc=False, revision=None):
    destination = destination.resolve()
    if revision is not None and not REVISION_RE.fullmatch(revision):
        raise ValueError('Cloud revision must be a 40-character commit SHA')
    if destination.exists():
        raise ValueError(f'Refusing to replace an existing destination: {destination}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(ATTEMPTS):
        print(f'Fetching canonical permissions: attempt {attempt + 1}/{ATTEMPTS}', flush=True)
        try:
            with tempfile.TemporaryDirectory(prefix='.permission-fetch-', dir=destination.parent) as folder:
                checkout = Path(folder) / 'checkout'
                deadline = time.monotonic() + ATTEMPT_TIMEOUT
                _git(['clone', '--depth=1', '--single-branch', '--branch=master',
                      '--filter=blob:none', '--no-checkout', SOURCE_URL, str(checkout)], deadline)
                paths = [PERMISSIONS_PATH, *(PRIVESC_PATHS if with_privesc or require_privesc else ())]
                _git(['-C', str(checkout), 'sparse-checkout', 'set', '--cone', *paths], deadline)
                if revision is not None:
                    _git(['-C', str(checkout), 'fetch', '--depth=1', 'origin', revision], deadline)
                _git(['-C', str(checkout), 'checkout', '--force', 'FETCH_HEAD' if revision else 'HEAD'], deadline)
                for provider in ('aws', 'gcp', 'azure', 'k8s'):
                    if not (checkout / 'src/permission-categorizations' / f'{provider}.yaml').is_file():
                        raise RuntimeError(f'Missing canonical file: {provider}.yaml')
                if require_privesc and not any((checkout / PRIVESC_PATHS[0] / provider).is_dir()
                                               for provider in ('aws', 'gcp', 'azure', 'k8s')):
                    raise RuntimeError(f'Missing canonical directory: {PRIVESC_PATHS[0]}')
                checkout.rename(destination)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as error:
            print(f'Fetch attempt {attempt + 1} failed: {error}', flush=True)
            if attempt == ATTEMPTS - 1:
                raise RuntimeError('Unable to fetch canonical permissions after five attempts') from error
            delay = BACKOFF_SECONDS[attempt]
            print(f'Retrying in {delay} seconds', flush=True)
            time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=Path('.canonical-source'))
    parser.add_argument('--with-privesc', action='store_true',
                        help='also fetch src/privilege-escalation-paths-cspm-reviewed and its source pages')
    parser.add_argument('--require-privesc', action='store_true',
                        help='like --with-privesc, but retry and fail when the privesc directory is missing')
    parser.add_argument('--revision-file', type=Path,
                        help='JSON manifest containing the exact Cloud commit SHA to fetch')
    args = parser.parse_args()
    revision = None
    if args.revision_file:
        revision = json.loads(args.revision_file.read_text())['revision']
    fetch(args.destination, with_privesc=args.with_privesc, require_privesc=args.require_privesc,
          revision=revision)


if __name__ == '__main__':
    main()
