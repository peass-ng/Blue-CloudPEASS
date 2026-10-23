"""Distinct finding/group counts without overlapping per-status ID sets."""
_GROUPS = ('FAIL', 'PASS', 'UNKNOWN,MANUAL', 'DENIED', 'NOT_APPLICABLE,EMPTY')
_BITS = {'FAIL': 1, 'PASS': 2, 'UNKNOWN': 4, 'MANUAL': 4, 'DENIED': 8,
    'NOT_APPLICABLE': 16, 'EMPTY': 16}
_GROUP_FOR_BIT = dict(zip((1, 2, 4, 8, 16), _GROUPS))


class FindingStatusCounts:
    def __init__(self):
        self._masks = {}
        self._counts = dict.fromkeys(_GROUPS, 0)

    def add(self, status, identity):
        bit = _BITS.get(status, 0)
        previous = self._masks.get(identity)
        if previous is None:
            self._masks[identity] = bit
            if bit:
                self._counts[_GROUP_FOR_BIT[bit]] += 1
        elif bit and not previous & bit:
            self._masks[identity] = previous | bit
            self._counts[_GROUP_FOR_BIT[bit]] += 1

    def result(self):
        return dict(self._counts)

    @property
    def total(self):
        return len(self._masks)
