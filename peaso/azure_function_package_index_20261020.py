"""Owner admission for ordinary portable package snapshots and normal indexes.

Live expected context is a separate caller-owned input. Offline JSON is ordinary
supplied snapshot assertion evidence with an explicit weaker provenance label;
it never grants source-read authority or claims independent context admission.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from . import azure_function_package_portable_20261020 as contract

_EXPECTED = ContextVar('azure_package_expected_context', default=())
INDEX_KEY = '_azure_package_owner_admission'
EXPORT = contract.KIND + '_export'


class _Admitted:
    __slots__ = ('snapshot', 'expected', 'scope')

    def __init__(self, snapshot, expected, scope):
        self.snapshot, self.expected, self.scope = snapshot, deepcopy(expected), scope


class _Assertions(_Admitted):
    """Supplied offline facts, deliberately distinct from native owner context."""
    __slots__ = ()


def retain_expected_context(expected):
    """Trusted Python boundary; never call using context extracted from JSON."""
    contract.validate_context(expected)
    prior = tuple(c for c in _EXPECTED.get() if c['capture'] != expected['capture'])
    _EXPECTED.set((*prior[-15:], deepcopy(expected)))


@contextmanager
def owner_admission(expected):
    """Independent saved-JSON replay supplies its separately retained context."""
    token = _EXPECTED.set(())
    try:
        retain_expected_context(expected)
        yield
    finally:
        _EXPECTED.reset(token)


def forget_expected_context(capture):
    _EXPECTED.set(tuple(c for c in _EXPECTED.get() if c['capture'] != capture))


def package_slice(snapshot, expected):
    metadata = snapshot['metadata']
    stamp = metadata[EXPORT]
    contract.require(set(stamp) == {'created_at', 'snapshot_id'})
    selected = [c for c in snapshot['collections'] if c['type'] == contract.KIND]
    contract.bounded({'collections': selected, 'metadata': metadata[contract.KIND], 'stamp': stamp})
    result = {'schema_version': '1.0', 'provider': 'azure',
              'scopes': deepcopy(expected['scopes']), 'created_at': stamp['created_at'],
              'snapshot_id': stamp['snapshot_id'],
              'collections': deepcopy(selected),
              'metadata': {contract.KIND: deepcopy(metadata[contract.KIND])}}
    contract.validate_snapshot(result, expected)
    return result


def attach(index, snapshot, scope):
    """Engine-only attachment validates the supplied snapshot against owner state."""
    if snapshot.get('provider') != 'azure' or contract.KIND not in snapshot.get('metadata', {}):
        return
    try:
        capture = snapshot['metadata'][contract.KIND]['index_context']['capture']
        retained = [c for c in _EXPECTED.get() if c['capture'] == capture and scope in c['scopes']]
        if retained:
            expected, = retained
            admission = _Admitted
        else:
            # This is explicitly an assertion from the same JSON document.
            # It is never described as independently retained native context.
            asserted = snapshot['metadata'][contract.KIND]['index_context']
            contract.bounded(asserted)
            expected = deepcopy(asserted)
            contract.validate_context(expected)
            contract.require(scope in expected['scopes'])
            admission = _Assertions
        selected = package_slice(snapshot, expected)
        index[INDEX_KEY] = admission(selected, expected, scope)
    except (KeyError, TypeError, ValueError, AttributeError):
        # Missing owner context is unavailable evidence, never self-admission.
        return
