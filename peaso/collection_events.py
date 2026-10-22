"""Private in-process handoff of settled native collection envelopes.

The callback is installed only by the scan worker. It sees native facts so it
must publish through the worker's public snapshot and credential redaction
boundary; it is never a progress event or a field in a saved connector.
"""
from contextlib import contextmanager
from contextvars import ContextVar


_scope_plan_callback = ContextVar('peaso_scope_plan_callback', default=None)


@contextmanager
def scope_plan_callback(callback):
    """Bind a worker-only discovery callback to this synchronous collection.

    Unlike connector options or progress, this channel never crosses a public
    serialization boundary. Nested collections restore their caller's binding.
    """
    if callback is not None and not callable(callback):
        raise TypeError('internal scope plan callback must be callable')
    token = _scope_plan_callback.set(callback)
    try:
        yield
    finally:
        _scope_plan_callback.reset(token)


def emit_scope_plan(scopes):
    callback = _scope_plan_callback.get()
    if callback is not None:
        callback(scopes)


def emit_collection(callback, envelope):
    if callback is not None:
        if not callable(callback):
            raise TypeError("internal collection callback must be callable")
        callback(envelope)


class SettledCollections(list):
    """Emit kept Azure envelopes after scheduler caps and direct projections.

    A few parent rows are enriched in place later, so their first append waits
    for collect_snapshot's final replay instead of publishing an incomplete
    version under a successful status.
    """

    def __init__(self, callback=None, *, deferred=()):
        super().__init__()
        self.callback = callback
        self.deferred = frozenset(deferred)

    def append(self, envelope):
        super().append(envelope)
        if envelope.get("type") not in self.deferred:
            emit_collection(self.callback, envelope)

    def extend(self, envelopes):
        for envelope in envelopes:
            self.append(envelope)


def completed_reads(rows, *, preserve_order=False):
    """Reduce ready provider reads immediately unless a global item cap needs order."""
    if preserve_order:
        yield from rows
        return
    from concurrent.futures import as_completed
    indexed = {row[-1]: row for row in rows}
    if len(indexed) != len(rows):
        raise ValueError("Native read futures must have distinct projections")
    for future in as_completed(indexed):
        yield indexed[future]
