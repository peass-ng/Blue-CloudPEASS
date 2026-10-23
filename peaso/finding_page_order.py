"""Stable finding pages without sorting every matching row for small pages."""
from heapq import nsmallest

_SEVERITY = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'informational': 4}


class _Descending:
    __slots__ = ('value',)

    def __init__(self, value):
        self.value = value

    def __lt__(self, other):
        return self.value > other.value

    def __eq__(self, other):
        return self.value == other.value


def _value(card, sort_by):
    if sort_by == 'severity':
        value = str(card.get('severity') or '').casefold()
        return _SEVERITY.get(value, 5), value
    if sort_by == 'resource_id':
        value = card.get('resource_name') or card.get('native_resource_id') or card.get('resource_id') or ''
    else:
        value = card.get(sort_by) or ''
    return str(value).casefold()


def _monotonic(values):
    return (all(not right < left for left, right in zip(values, values[1:]))
            or all(not left < right for left, right in zip(values, values[1:])))


def _ordered_sample(rows, key, *, explicit):
    # Timsort is linear on ordered data. Keep that path when a small sample
    # suggests both legacy sorting passes can take advantage of native runs.
    sample = [rows[(len(rows) - 1) * i // 31] for i in range(32)]
    try:
        if explicit and not _monotonic([row[1]['id'] for row in sample]):
            return False
        return _monotonic([key(row) for row in sample])
    except (TypeError, KeyError, AttributeError):
        return True


def finding_page(rows, *, group_by='service', sort_by=None, sort_order='asc', offset=0, limit=500):
    """Return the same page as the API's stable full sorts.

    Explicit sorts keep IDs ascending within either primary direction. Large
    pages and unusual archived IDs retain the complete original sorting path.
    The caller still computes filters, totals, facets and groups over all rows.
    """
    end = offset + limit
    if len(rows) >= 4096 and offset >= 0 and limit > 0 and end <= 4096 and end * 16 <= len(rows):
        if sort_by is None:
            key = lambda pair: (str(pair[1].get(group_by, '')), pair[1]['id'])
        elif sort_order == 'desc':
            key = lambda pair: (_Descending(_value(pair[1], sort_by)), pair[1]['id'])
        else:
            key = lambda pair: (_value(pair[1], sort_by), pair[1]['id'])
        if (not _ordered_sample(rows, key, explicit=sort_by is not None)
                and all(type(pair[1].get('id')) is str for pair in rows)):
            return nsmallest(end, rows, key=key)[offset:end]
    if sort_by is None:
        rows.sort(key=lambda pair: (str(pair[1].get(group_by, '')), pair[1]['id']))
    else:
        rows.sort(key=lambda pair: pair[1]['id'])
        rows.sort(key=lambda pair: _value(pair[1], sort_by), reverse=sort_order == 'desc')
    return rows[offset:end]
