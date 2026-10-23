"""Ordered candidates for Kubernetes workload correlation, local to one run."""
from functools import partial

from .resource_index import OrderedMatchIndex

MAX_LABEL_KEYS = 200000
MIN_LABEL_ROWS = 8


def _recorded_scope(row, cluster_of):
    return cluster_of(row), row['data'].get('metadata', {}).get('namespace', 'default')


class K8sWorkloadIndex:
    def __init__(self, snapshot, by_type, cluster_of):
        self.snapshot, self.by_type, self.cluster_of = snapshot, by_type, cluster_of
        self.indexes, self.pod_labels = {}, {}
        self.bad_scope, self.bad_labels = object(), object()
        self.policy_collections, self.policy_complete = None, {}
        self.remaining_label_keys = MAX_LABEL_KEYS

    def _scope(self, row):
        return _recorded_scope(row, self.cluster_of)

    @staticmethod
    def _keys(row, *, named, cluster_of, bad_scope):
        try:
            key = _recorded_scope(row, cluster_of)
            if named:
                key = (*key, row['data'].get('metadata', {}).get('name'))
                hash(key)
            return [key]
        except (KeyError, TypeError, AttributeError):
            # Keep malformed rows as candidates. The original predicate must
            # still decide whether it visits them, including next() ordering.
            return [bad_scope]

    def candidates(self, kind, owner, *, names=None):
        rows = self.by_type[kind]
        if not rows:
            return []
        try:
            scope = self._scope(owner)
        except (KeyError, TypeError, AttributeError):
            return rows
        named = names is not None
        index = self.indexes.get((kind, named))
        if index is None:
            # Callback values must not retain this owner through an index
            # cycle: privilege analysis deliberately pauses cyclic GC.
            keys_of = partial(self._keys, named=named, cluster_of=self.cluster_of, bad_scope=self.bad_scope)
            index = self.indexes[kind, named] = OrderedMatchIndex(rows, keys_of)
        keys = [(*scope, name) for name in names] if named else [scope]
        return index.matching([*keys, self.bad_scope])

    @staticmethod
    def _label_keys(pod, *, bad_labels):
        labels = pod['data'].get('metadata', {}).get('labels', {})
        if not isinstance(labels, dict):
            return [bad_labels]
        return [('label', key, value) for key, value in labels.items()]

    def pods(self, service):
        data = service['data']
        selector = (data.get('spec') or {}).get('selector')
        meta = data.get('metadata') or {}
        if not selector:
            return []
        rows = self.by_type['pod']
        if not rows:
            return []
        try:
            scope = self._scope(service)
            hash(scope)
        except (KeyError, TypeError, AttributeError):
            # Invalid owner metadata retains the original literal evaluation.
            return [pod for pod in rows if self.cluster_of(pod) == self.cluster_of(service)
                and pod['data'].get('metadata', {}).get('namespace', 'default') == meta.get('namespace', 'default')
                and all(pod['data'].get('metadata', {}).get('labels', {}).get(k) == v for k, v in selector.items())]
        cached = self.pod_labels.get(scope)
        if cached is None:
            scoped = [pod for pod in self.candidates('pod', service) if self.cluster_of(pod) == self.cluster_of(service)
                and pod['data'].get('metadata', {}).get('namespace', 'default') == meta.get('namespace', 'default')]
            index = None
            if len(scoped) >= MIN_LABEL_ROWS:
                entries = 0
                for pod in scoped:
                    labels = pod['data'].get('metadata', {}).get('labels', {})
                    entries += len(labels) if isinstance(labels, dict) else 1
                if entries <= self.remaining_label_keys:
                    index = OrderedMatchIndex(scoped, partial(self._label_keys, bad_labels=self.bad_labels))
                    self.remaining_label_keys -= entries
                # Large scopes reuse their complete candidate set even when
                # label-index admission is exhausted. Small scopes remain cheap
                # through the global scope index and retain no per-scope cache.
                cached = self.pod_labels[scope] = (scoped, index)
            else:
                cached = scoped, None
        scoped, index = cached
        if not scoped:
            return []
        # A None selector also matches an absent key under the original get()
        # predicate, so only non-None values can safely nominate candidates.
        keys = [('label', k, v) for k, v in selector.items() if v is not None]
        candidates = index.smallest_matching(keys, always=[self.bad_labels]) if keys and index is not None else scoped
        return [pod for pod in candidates
                if all(pod['data'].get('metadata', {}).get('labels', {}).get(k) == v for k, v in selector.items())]

    def complete_policies(self, scope):
        try:
            cached = self.policy_complete.get(scope)
        except TypeError:
            return any(c.get('type') == 'networkpolicy' and c.get('scope') == scope
                and c.get('status') in {'collected', 'empty'} for c in self.snapshot.get('collections', []))
        if cached is not None:
            return cached
        if self.policy_collections is None:
            self.policy_collections = {}
            for collection in self.snapshot.get('collections', []):
                if collection.get('type') == 'networkpolicy':
                    self.policy_collections.setdefault(collection.get('scope'), []).append(collection)
        complete = any(c.get('status') in {'collected', 'empty'} for c in self.policy_collections.get(scope, []))
        self.policy_complete[scope] = complete
        return complete
