"""A lowercase view owned by one mutable, scan-local trust boundary.

Only ordinary string normalization is retained, never a trust decision. All
normal set mutation methods invalidate the view, including partial failures.
Caller-supplied sets and string subclasses retain fresh normalization.
"""
import copy
from functools import wraps
from threading import RLock


class OwnedDomains(set):
    __slots__ = ('_lock', '_lowered', '_mutating', '_epoch')

    def __init__(self, values=()):
        if not hasattr(self, '_lock'):
            self._lock = RLock()
            self._lowered = None
            self._mutating = 0
            self._epoch = 0
        self._change(set.__init__, values)

    def _change(self, operation, *args, **kwargs):
        with self._lock:
            self._lowered = None
            self._mutating += 1
            self._epoch += 1
        # Iterables and element hash methods can call back into classification
        # or another thread. Do not hold the state lock across caller code.
        try:
            return operation(self, *args, **kwargs)
        finally:
            with self._lock:
                self._lowered = None
                self._mutating -= 1
                self._epoch += 1

    def lowered(self):
        cached = self._lowered
        if cached is not None:
            return cached
        with self._lock:
            cached = self._lowered
            if cached is not None:
                return cached
            epoch = self._epoch
        result = frozenset(domain.lower() for domain in self)
        # Custom lower() methods can change without a set mutation. Reentrant
        # iterables can inspect intermediate update() states; never retain one.
        with self._lock:
            if (epoch == self._epoch and not self._mutating
                    and all(type(domain) is str for domain in self)):
                self._lowered = result
        return result

    def __copy__(self):
        return set(self)

    def __deepcopy__(self, memo):
        result = set()
        memo[id(self)] = result
        for value in list(self):
            result.add(copy.deepcopy(value, memo))
        return result

    def __reduce__(self):
        return set, (list(self),)


def _mutation(operation):
    @wraps(operation)
    def change(self, *args, **kwargs):
        return self._change(operation, *args, **kwargs)
    return change


for _name in ('add', 'clear', 'discard', 'pop', 'remove', 'update', 'difference_update',
              'intersection_update', 'symmetric_difference_update', '__ior__', '__iand__',
              '__ixor__', '__isub__'):
    setattr(OwnedDomains, _name, _mutation(getattr(set, _name)))


def normalized(domains):
    if type(domains) is OwnedDomains:
        return domains.lowered()
    return {domain.lower() for domain in domains}
