"""Bounded count-only child progress, distinct from heartbeat and final results."""
from contextlib import contextmanager
import threading
import time
from peaso.progress import bind_callback, sanitize_event


def safe_event(event):
    result = sanitize_event(event)
    # Never transmit provider arguments, native facts, source paths or credentials.
    result.pop('scope', None)
    return {key: value for key, value in result.items()
            if key not in ('completed', 'total', 'resources') or value is None or value <= 2**63 - 1}


class ProgressStream:
    def __init__(self, connection, *, interval=2.0, clock=time.monotonic):
        self.connection, self.interval, self.clock = connection, interval, clock
        self.lock = threading.Lock()
        self.last_sent, self.last_phase, self.pending = float('-inf'), None, None

    def __call__(self, event):
        value = safe_event(event)
        if not value:
            return
        with self.lock:
            self.pending = value
            if value.get('phase') != self.last_phase or self.clock() - self.last_sent >= self.interval:
                self._flush()

    def _flush(self):
        if self.pending is None:
            return
        try:
            self.connection.send(('__progress__', self.pending))
            self.last_sent = self.clock()
            self.last_phase = self.pending.get('phase')
        except (OSError, EOFError):
            pass
        self.pending = None

    def flush(self):
        with self.lock:
            self._flush()


@contextmanager
def stream_progress(connection):
    stream = ProgressStream(connection)
    with bind_callback(stream):
        try:
            yield stream
        finally:
            stream.flush()


def record_progress(store, job, event, logger):
    value = safe_event(event)
    if not value:
        return
    logger.info('Scan progress: phase=%s provider=%s completed=%s total=%s resources=%s',
                value.get('phase', 'unknown'), value.get('provider', 'unknown'),
                value.get('completed'), value.get('total'), value.get('resources'))
    persist = getattr(store, 'record_progress', None)
    if callable(persist):
        try:
            persist(job['id'], job['owner'], value)
        except Exception:
            # Optional diagnostic storage never changes the assessment outcome.
            pass
