"""Read-only reverse joins that retain authoritative resource order."""
from heapq import merge
from array import array


class OrderedMatchIndex:
    """Build once on first use; preserve duplicate input rows and OR semantics.

    Keys only nominate rows. The caller supplies exact recorded relationship
    keys; this class never normalizes identities or infers scope inheritance.
    """
    def __init__(self, rows, keys, *, strict=False):
        self.rows, self.keys, self.strict = rows, keys, strict
        self.index = None

    def _build(self):
        index, fallback, indexed_rows = {}, [], []
        for position, row in enumerate(self.rows):
            indexed_rows.append(row)
            unhashable = []
            for key in self.keys(row):
                try:
                    run = index.get(key)
                    if run is None:
                        index[key] = position
                    elif type(run) is int:
                        index[key] = array('Q', (run, position))
                    else:
                        run.append(position)
                except TypeError:
                    if self.strict:
                        raise
                    unhashable.append(key)
            if unhashable:
                fallback.append((position, unhashable))
        self.index, self.fallback, self.indexed_rows = index, fallback, indexed_rows

    def matching(self, keys):
        if self.index is None:
            self._build()
        keys, runs, singletons = list(keys), [], None
        for key in keys:
            try:
                run = self.index.get(key, ())
                if type(run) is int:
                    if singletons is None:
                        singletons = run
                    elif type(singletons) is int:
                        singletons = [singletons, run]
                    else:
                        singletons.append(run)
                elif run:
                    runs.append(run)
            except TypeError:
                if self.strict:
                    raise
        if self.fallback:
            runs.append([position for position, recorded in self.fallback
                         if any(key in recorded for key in keys)])
        if not runs and type(singletons) is int:
            return [self.indexed_rows[singletons]]
        # A broad alias query can nominate thousands of one-row runs. Sort
        # those positions together instead of retaining a heap iterator per run.
        if type(singletons) is int:
            runs.append((singletons,))
        elif singletons is not None:
            singletons.sort()
            runs.append(singletons)
        result, previous = [], None
        for position in merge(*runs):
            if position != previous:
                result.append(self.indexed_rows[position])
            previous = position
        return result

    def smallest_matching(self, keys, *, always=()):
        """Candidates for an AND predicate; the caller must recheck every key.

        Select the least populated recorded key without materializing broad
        candidate lists. Unhashable keys remain supported by the exact matcher.
        """
        if self.index is None:
            self._build()
        keys = list(keys)
        if not keys:
            return list(self.rows)

        def size(key):
            try:
                run = self.index.get(key, ())
                return 1 if type(run) is int else len(run)
            except TypeError:
                return len(self.rows)

        return self.matching([min(keys, key=size), *always])
