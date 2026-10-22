"""Context-local, bounded offline preparation for the pinned TruffleHog scanner."""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import os
import sys
import tempfile


MAX_BATCH_ITEMS = 32
MAX_BATCH_BYTES = 64 * 1024 * 1024
_PREPARED_BATCH = ContextVar('prepared_content_batch', default=None)


def _after_fork():
    inherited = _PREPARED_BATCH.get()
    if inherited is not None:
        inherited.clear()
    _PREPARED_BATCH.set(None)


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork)


def prepared_output(payload, path):
    """Return exact-source NDJSON, including b'' for clean, or None for serial."""
    prepared = _PREPARED_BATCH.get()
    return None if prepared is None else prepared.get((payload, path))


def _volatile_shm_available(total):
    """Require the exact /dev/shm mount to be volatile, with spare capacity."""
    if sys.platform != 'linux' or os.path.islink('/dev/shm') or not os.path.ismount('/dev/shm'):
        return False
    with open('/proc/self/mountinfo', encoding='utf-8') as mounts:
        if not any(line.split(' - ', 1)[0].split()[4] == '/dev/shm'
                   and line.split(' - ', 1)[1].split()[0] == 'tmpfs'
                   for line in mounts if ' - ' in line):
            return False
    space = os.statvfs('/dev/shm')
    return space.f_bavail * space.f_frsize >= total + 1024 * 1024


def _prepare_trufflehog_batch(items, timeout):
    # Import lazily: secret_scanning exports this module's context manager.
    from . import secret_scanning as scanning

    items = list(dict.fromkeys(items))
    total = sum(len(payload) for payload, _ in items)
    if not _volatile_shm_available(total):
        return None
    with tempfile.TemporaryDirectory(prefix='peaso-scan-', dir='/dev/shm') as directory:
        os.chmod(directory, 0o700)
        paths = {}
        for index, (payload, original_path) in enumerate(items):
            filename = os.path.join(directory, str(index))
            fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, 'wb') as staged:
                    staged.write(payload)
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            paths[filename] = (payload, original_path)
        output = scanning._run([scanning._trufflehog(), 'filesystem', '--json',
                                '--no-verification', '--no-update', '--log-level=-1',
                                '--concurrency=1', '--force-skip-archives',
                                '--no-verification-cache', '--fail-on-scan-errors',
                                *paths], b'', timeout)
        grouped = {item: [] for item in items}
        for line in output.splitlines():
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError('invalid batch detector result')
            source = row.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file')
            if not isinstance(source, str) or source not in paths:
                raise ValueError('invalid batch source')
            if not isinstance(row.get('Raw'), str) or not row['Raw'] or row.get('Verified') is not False:
                raise ValueError('invalid offline detector result')
            grouped[paths[source]].append(line)
        return {item: b'\n'.join(lines) for item, lines in grouped.items()}


@contextmanager
def prepared_content_batch(items, *, timeout=60):
    """Prepare bounded per-source TruffleHog output for exact scan_content calls.

    Unsupported hosts or failed preparation use the existing serial scanner.
    No staged payload file survives entry to this context.
    """
    if (not isinstance(items, list) or len(items) > MAX_BATCH_ITEMS
            or not 0 < timeout <= 60):
        raise ValueError('content batch bound')
    total = 0
    for item in items:
        if (not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], bytes)
                or not isinstance(item[1], str) or len(item[0]) > MAX_BATCH_BYTES):
            raise ValueError('content batch bound')
        total += len(item[0])
        if total > MAX_BATCH_BYTES:
            raise ValueError('content batch bound')
    prepared = None
    if len(items) > 1:
        try:
            prepared = _prepare_trufflehog_batch(items, timeout)
        except Exception:
            # Every item returns to the original serial scanner on batch failure.
            prepared = None
    token = _PREPARED_BATCH.set(prepared)
    try:
        yield
    finally:
        _PREPARED_BATCH.reset(token)
        if prepared is not None:
            prepared.clear()
