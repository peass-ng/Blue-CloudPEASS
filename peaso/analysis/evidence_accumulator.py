"""Ordered, append-only evidence with exact equality inside candidate buckets."""

MAX_KEYS = 200_000
MAX_SEQUENCES = 8192
MIN_INDEXED_ROWS = 8
_UNSUPPORTED = object()
_MISSING = object()


def _key(kind, item):
    if kind == 'scope':
        return item if type(item) is str else _UNSUPPORTED
    if type(item) is not dict:
        return _UNSUPPORTED
    if kind == 'review':
        fields = tuple(item.get(name) for name in ('resource_id', 'scope', 'grant_source_id'))
        count = item.get('grant_count')
        return (*fields, count) if all(type(value) is str for value in fields) and type(count) is int else _UNSUPPORTED
    fields = tuple(item.get(name) for name in ('kind', 'state', 'resource_id', 'scope'))
    optional = tuple(item.get(name) for name in ('endpoint_resource', 'caller'))
    if all(type(value) is str for value in fields) and all(value is None or type(value) is str for value in optional):
        return fields + optional
    return _UNSUPPORTED


class EvidenceAccumulator:
    """Temporary indexes; native grants, conditions and output order stay intact.

    Unsupported keys and exhausted budgets use the original complete-list
    membership predicate. Indexes never truncate or serialize evidence.
    """
    def __init__(self):
        self.indexes = {}
        self.remaining = MAX_KEYS
        self.max_sequences = MAX_SEQUENCES

    def append(self, rows, item, kind):
        # Most principals have only one scope or signal. Build an index only
        # when repeated list membership can justify its retained allocations.
        if len(rows) < MIN_INDEXED_ROWS:
            if item not in rows:
                rows.append(item)
            return
        token = kind, id(rows)
        if token not in self.indexes:
            if len(self.indexes) >= self.max_sequences:
                if item not in rows:
                    rows.append(item)
                return
            index = {}
            for row in rows:
                key = _key(kind, row)
                if key is _UNSUPPORTED or self.remaining <= 0:
                    index = None
                    break
                bucket = index.get(key, _MISSING)
                if bucket is _MISSING:
                    index[key] = row
                elif type(bucket) is list:
                    bucket.append(row)
                else:
                    index[key] = [bucket, row]
                self.remaining -= 1
            # Retain the list identity until this projection ends.
            self.indexes[token] = rows, index
        index = self.indexes[token][1]
        key = _key(kind, item) if index is not None else _UNSUPPORTED
        if key is _UNSUPPORTED:
            self.indexes[token] = rows, None
            if item not in rows:
                rows.append(item)
            return
        bucket = index.get(key, _MISSING)
        if bucket is not _MISSING:
            if type(bucket) is list:
                if item in bucket:
                    return
            elif bucket is item or bucket == item:
                return
        rows.append(item)
        if self.remaining <= 0:
            self.indexes[token] = rows, None
        else:
            if bucket is _MISSING:
                index[key] = item
            elif type(bucket) is list:
                bucket.append(item)
            else:
                index[key] = [bucket, item]
            self.remaining -= 1
