"""Ordered service-account candidates for declared Kubernetes impersonation.

Indexes nominate candidates only. The caller still checks the original rule,
cluster, namespace and resourceNames predicates, including malformed evidence.
"""
from functools import partial

from peaso.snapshot import FrozenDict, FrozenList
from .resource_index import OrderedMatchIndex

MAX_KEYS = 200000
MAX_BYTES = 16 * 1024 * 1024
MAX_QUERY_NAMES = 4096
_BAD = object()


class _Capacity(Exception):
    pass


def _keys(row, *, cluster_of, scoped, named, budget):
    try:
        if type(row) not in (dict, FrozenDict) or type(row['data']) not in (dict, FrozenDict):
            raise TypeError
        data = row['data']
        meta = data.get('metadata')
        provenance = data.get('provenance')
        if meta is None:
            meta = {}
        if provenance is None:
            provenance = {}
        if type(meta) not in (dict, FrozenDict) or type(provenance) not in (dict, FrozenDict):
            raise TypeError
        if (type(row.get('scope')) is not str
                or any(value is not None and type(value) is not str
                       for value in (meta.get('cluster_id'), provenance.get('cluster_id')))):
            raise TypeError
        namespace = meta.get('namespace', 'default')
        key = (cluster_of(row),)
        if scoped:
            if type(namespace) is not str:
                raise TypeError
            key += (namespace,)
        if named:
            name = meta.get('name')
            if type(name) is not str:
                raise TypeError
            key += (name,)
        if any(type(value) is not str or len(value) > 1024 for value in key):
            raise TypeError
    except (KeyError, TypeError, AttributeError):
        key = _BAD
    size = 96 + (sum(len(value) * 4 for value in key) if key is not _BAD else 0)
    if budget[0] <= 0 or budget[1] < size:
        raise _Capacity
    budget[0] -= 1
    budget[1] -= size
    return [key]


class K8sImpersonationIndex:
    def __init__(self, accounts, cluster_of):
        self.accounts, self.cluster_of = accounts, cluster_of
        self.indexes = {}
        self.budget = [MAX_KEYS, MAX_BYTES]

    def candidates(self, binding, namespace, names):
        if not self.accounts:
            return self.accounts
        scoped = binding['type'] == 'rolebinding'
        # Native resourceNames is an equality list. Other recorded shapes can
        # have different membership semantics and retain the literal predicate.
        named = (type(names) in (list, FrozenList, tuple) and 0 < len(names) <= MAX_QUERY_NAMES
                 and all(type(name) is str for name in names))
        try:
            key = (self.cluster_of(binding), namespace) if scoped else (self.cluster_of(binding),)
            if any(type(value) is not str or len(value) > 1024 for value in key):
                return self.accounts
        except (KeyError, TypeError, AttributeError):
            return self.accounts
        relation = scoped, named
        if relation not in self.indexes:
            # Capture the function and budget, not this owner: analysis can
            # disable cyclic GC while computing privilege projections.
            self.indexes[relation] = OrderedMatchIndex(self.accounts, partial(
                _keys, cluster_of=self.cluster_of, scoped=scoped, named=named, budget=self.budget))
        index = self.indexes[relation]
        if index is None:
            return self.accounts
        keys = [(*key, name) for name in dict.fromkeys(names)] if named else [key]
        try:
            return index.matching([*keys, _BAD])
        except _Capacity:
            # This limits index memory, never the accounts or recorded signals.
            self.indexes[relation] = None
            return self.accounts
