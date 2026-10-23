"""Ordered candidates for endpoint-to-runtime identity joins.

The caller rechecks its original predicates. Malformed rows remain candidates so
an index cannot turn missing or invalid evidence into a clean negative result.
"""
from functools import partial

from peaso.analysis.resource_index import OrderedMatchIndex
from peaso.snapshot import FrozenDict

MAX_KEYS = 200_000
_BAD = object()


class _Capacity(Exception):
    pass


def compute_path(value):
    return value.split("/compute/v1/", 1)[-1] if isinstance(value, str) and "/compute/v1/" in value else None


def _values(row, field, lower, wrapper):
    if field in {'azure_federation_app_id', 'azure_federation_identity_id'}:
        # These joins use sealed native identity fields. Unusual or mutable
        # sources remain candidates for the original caller predicate.
        if type(row) not in (dict, FrozenDict) or type(row['data']) is not FrozenDict:
            yield _BAD
        else:
            native_field = 'appId' if field == 'azure_federation_app_id' else 'id'
            value = row['data'].get(native_field)
            if type(value) is not str or len(value) > 4096:
                yield _BAD
            else:
                yield value.lower() if lower else value
    elif field in {'gcp_backend_path', 'gcp_running_instance_path'}:
        scope = row['scope']
        if field == 'gcp_backend_path' or row['data'].get('status') == 'RUNNING':
            yield scope, compute_path(row['data'].get('selfLink'))
    elif field == 'target_group_lb':
        references = row['data'].get('LoadBalancerArns') or []
        # Native strings have substring-membership semantics in the original
        # predicate. Keep those rows for exact evaluation by every caller.
        if not isinstance(references, (list, tuple)):
            yield _BAD
        else:
            yield from references
    elif field == 'ecs_service_target_group':
        for binding in row['data'].get('loadBalancers') or []:
            yield binding.get('targetGroupArn')
    elif field == 'running_task_definition':
        if row['data'].get('lastStatus') == 'RUNNING':
            yield row['data'].get('taskDefinitionArn')
    elif field == 'running_task_eni':
        data = row['data']
        if data.get('lastStatus') == 'RUNNING':
            for attachment in data.get('attachments') or []:
                for detail in attachment.get('details') or []:
                    if detail.get('name') == 'networkInterfaceId':
                        yield detail.get('value')
    else:
        value = row[field] if wrapper else row['data'].get(field, '' if lower else None)
        yield str(value).lower() if lower else value


def _keys(row, *, field, lower, wrapper, budget):
    try:
        for value in _values(row, field, lower, wrapper):
            hash(value)
            if budget[0] <= 0:
                raise _Capacity
            budget[0] -= 1
            yield value
    except (KeyError, TypeError, AttributeError):
        if budget[0] <= 0:
            raise _Capacity
        budget[0] -= 1
        yield _BAD


class CloudWorkloadIndex:
    def __init__(self, by_type):
        self.by_type = by_type
        self.indexes = {}
        self.budget = [MAX_KEYS]

    def candidates(self, kind, field, values, *, lower=False, wrapper=False):
        rows = self.by_type[kind]
        if not rows:
            return rows
        values = list(values)
        if lower:
            # Leave native non-string reference behavior to the caller, including
            # its short circuits and first-match handling.
            if any(not isinstance(value, str) for value in values):
                return rows
            values = [value.lower() for value in values]
        try:
            for value in values:
                hash(value)
        except TypeError:
            return rows
        relation = kind, field, lower, wrapper
        if relation not in self.indexes:
            self.indexes[relation] = OrderedMatchIndex(rows, partial(
                _keys, field=field, lower=lower, wrapper=wrapper, budget=self.budget))
        index = self.indexes[relation]
        if index is None:
            return rows
        try:
            return index.matching([*values, _BAD])
        except _Capacity:
            # Fall back to the complete inventory; never truncate evidence.
            self.indexes[relation] = None
            return rows
