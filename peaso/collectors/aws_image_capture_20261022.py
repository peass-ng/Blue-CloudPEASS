"""One bounded private payload capture per exact ECR image during dispatch.

Only paths live here; public request Futures still contain safe projections.
The collector must enclose all consumers (and their executor shutdown) in scope.
Without that owner, existing independently owned temporary downloads apply.
"""
from contextlib import contextmanager
from pathlib import Path
import shutil
import tempfile
import threading

MAX_CAPTURE_BYTES = 16 * 1024 * 1024 * 1024
MAX_CAPTURE_BLOBS = 32768
FREE_RESERVE_BYTES = 512 * 1024 * 1024


def _authority(session):
    # Only the reviewed wrapper delegates authority to its original session.
    from .aws_workload_image_secret_native_20261021 import _PinnedSession
    return session.session if type(session) is _PinnedSession else session


class _Capture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='peaso-ecr-capture-')
        self.root = Path(self.temporary.name)
        # Leave at least half the currently available scratch for archive
        # construction and scanners; 16 GiB is a ceiling, never a reservation.
        try:
            self.capacity = min(MAX_CAPTURE_BYTES, max(0,
                (shutil.disk_usage(self.root).free - FREE_RESERVE_BYTES) // 2))
        except Exception:
            self.temporary.cleanup()
            raise
        self.lock = threading.Lock()
        self.entries, self.sessions, self.reserved = {}, [], 0
        self.closed = False

    def blob(self, requests, session, account, region, repo, image_digest, digest, size, load,
             *, check=None):
        check = check or requests.check_deadline
        check()
        authority = _authority(session)
        key = (id(authority), account, region, repo, image_digest, digest)
        with self.lock:
            if self.closed:
                raise ValueError('image_capture_closed')
            entry = self.entries.get(key)
            owner = entry is None
            if owner:
                if (type(size) is not int or size <= 0 or
                        self.reserved + size > self.capacity or
                        len(self.entries) >= MAX_CAPTURE_BLOBS):
                    raise ValueError('image_capture_bound')
                self.sessions.append(authority)  # Prevent session id recycling.
                self.reserved += size
                entry = self.entries[key] = {
                    'ready': threading.Event(), 'size': size, 'ok': False,
                    'path': self.root / ('blob-' + str(len(self.entries)))}
            elif entry['size'] != size:
                raise ValueError('image_capture_descriptor_changed')
        if owner:
            try:
                load(entry['path'])
                if not entry['path'].is_file() or entry['path'].stat().st_size != size:
                    raise ValueError('image_capture_incomplete')
                entry['ok'] = True
            finally:
                try:
                    if not entry['ok']:
                        entry['path'].unlink(missing_ok=True)
                finally:
                    entry['ready'].set()
        else:
            while not entry['ready'].wait(0.1):
                check()
        check()
        requests.check_deadline()
        if not entry['ok']:
            raise ValueError('image_capture_unavailable')
        return entry['path']

    def close(self):
        with self.lock:
            self.closed = True
        try:
            self.temporary.cleanup()
        finally:
            self.entries.clear()
            self.sessions.clear()


@contextmanager
def capture_scope(requests):
    """Own private files until every dispatched consumer has stopped.

    Enter before the executor contexts so executor shutdown precedes cleanup.
    Cleanup errors propagate; a collector must not claim complete capture then.
    """
    with requests._lock:
        if getattr(requests, '_ecr_image_capture', None) is not None:
            raise ValueError('image_capture_already_owned')
        capture = _Capture()
        requests._ecr_image_capture = capture
    try:
        yield capture
    finally:
        try:
            capture.close()
        finally:
            with requests._lock:
                del requests._ecr_image_capture


def shared_blob(requests, session, account, region, repo, image_digest,
                digest, size, load, fallback, *, check=None):
    """Reuse only after the caller independently authorized its exact manifest."""
    capture = getattr(requests, '_ecr_image_capture', None)
    if capture is None:
        return load(fallback)
    return capture.blob(requests, session, account, region, repo,
                        image_digest, digest, size, load, check=check)
