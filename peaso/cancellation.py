"""CLI signals cancel provider reads before unwinding scan-owned cleanup."""
from contextlib import contextmanager
from contextvars import ContextVar
import signal
import threading

_current = ContextVar('peaso_collection_cancellation', default=None)


def current_event():
    return _current.get()


@contextmanager
def collection_cancellation():
    event = threading.Event()
    token = _current.set(event)
    previous = {}
    received = []
    if threading.current_thread() is threading.main_thread():
        def stop(signum, _frame):
            received.append(signum)
            event.set()
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, stop)
    try:
        yield received
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        _current.reset(token)
