"""The signed routing predicate has no mandatory owner action-group parameter."""
import pytest
from tests.compliance_draft_isolation import staged_registry
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


@pytest.fixture
def routing():
    with staged_registry(['compliance_new_sw25']):
        from tests.test_peaso_compliance_new_sw25 import fixture, SCOPE, NOW, GROUP
        from peaso.checks.compliance_new_sw25_facts import ROUTING_ID
        yield fixture(ROUTING_ID), SCOPE, NOW, GROUP, ROUTING_ID


def verdict(case):
    index, scope, now, _, cid = case
    collections = [c for envelopes in index['collections'].values() for c in envelopes]
    snapshot = make_snapshot('azure', [scope], collections,
        metadata=index['context']['metadata'], created_at=now)
    return next(f['status'] for f in evaluate_snapshot(snapshot, checks=[cid])['findings'] if f['check_id'] == cid)


def test_completely_absent_owner_policy_allows_native_routing_pass(routing):
    routing[0]['context']['metadata'].pop('sw25_policy')
    assert verdict(routing) == 'PASS'


def test_other_policy_namespace_does_not_require_routing_parameter(routing):
    metadata = routing[0]['context']['metadata']
    metadata.pop('sw25_policy')
    metadata['compliance_policy'] = {'sw16': {}}
    assert verdict(routing) == 'PASS'


@pytest.mark.parametrize('mode', ['legacy_null', 'legacy_string', 'legacy_foreign', 'normative_denied',
    'normative_foreign', 'normative_missing_check', 'normative_wrong_shape', 'malformed_parent'])
def test_supplied_bad_policy_is_never_discarded_as_absent(routing, mode):
    index, scope, _, _, cid = routing
    metadata = index['context']['metadata']
    if mode == 'legacy_null': metadata['sw25_policy'] = None
    elif mode == 'legacy_string': metadata['sw25_policy'] = 'invalid'
    elif mode == 'legacy_foreign': metadata['sw25_policy'][cid]['scope'] = '/subscriptions/other'
    else:
        metadata.pop('sw25_policy')
        review = {'status': 'collected', 'scope': scope, 'checks': {cid: {}}}
        metadata['compliance_policy'] = {'sw25': review}
        if mode == 'normative_denied': review['status'] = 'denied'
        elif mode == 'normative_foreign': review['scope'] = '/subscriptions/other'
        elif mode == 'normative_missing_check': review['checks'] = {}
        elif mode == 'normative_wrong_shape': metadata['compliance_policy']['sw25'] = []
        elif mode == 'malformed_parent': metadata['compliance_policy'] = None
    assert verdict(routing) == 'UNKNOWN'


@pytest.mark.parametrize('match,expected', [(True, 'PASS'), (False, 'FAIL')])
def test_explicit_normative_action_group_is_respected(routing, match, expected):
    index, scope, _, group, cid = routing
    metadata = index['context']['metadata']
    metadata.pop('sw25_policy')
    metadata['compliance_policy'] = {'sw25': {'status': 'collected', 'scope': scope,
        'checks': {cid: {'actionGroupId': group if match else group + '-other'}}}}
    assert verdict(routing) == expected
