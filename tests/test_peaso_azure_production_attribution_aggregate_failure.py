"""Registered production attribution aggregates decisive and unresolved changes."""
import pytest

from peaso.checks import evaluate_check


CID = 'azure_c5_dev_08_02b'
SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
RESOURCE = SCOPE + '/resourceGroups/rg/providers/Microsoft.Web/sites/app'
WHEN = '2026-10-05T00:00:00Z'


def change(suffix, *, status='Succeeded'):
    return {'id': SCOPE + '/providers/PEASO/changes/' + suffix,
            'resourceId': RESOURCE, 'timestamp': WHEN, 'correlationId': suffix,
            'actorId': 'actor', 'status': status}


def activity(suffix):
    return {'id': 'azure-activity://' + suffix, 'resourceId': RESOURCE,
            'correlationId': suffix, 'caller': 'actor',
            'operationName': {'value': 'Microsoft.Web/sites/write'},
            'status': {'value': 'Succeeded'}, 'eventTimestamp': WHEN}


def facts(changes, activities):
    rows = {'production_change': changes, 'activity_log': activities}
    policy = {'window_start': '2026-10-01T00:00:00Z',
              'window_end': '2026-10-10T00:00:00Z',
              'productionResourceIds': [RESOURCE], 'dataPlaneChangesComplete': True}
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
                         'created_at': '2026-10-12T00:00:00Z',
                         'metadata': {'compliance_policy': {'sw26': {
                             'status': 'collected', 'scope': SCOPE, CID: policy}}}},
             'collections': {}}
    for kind, items in rows.items():
        index['collections'][kind] = [{'type': kind, 'scope': SCOPE,
                                       'status': 'collected' if items else 'empty', 'items': items}]
        index[kind] = [{'type': kind, 'scope': SCOPE, 'data': item} for item in items]
    return index


@pytest.mark.parametrize('order', [('a', 'b'), ('b', 'a')])
def test_missing_activity_failure_survives_unresolved_change_state(order):
    status, evidence = evaluate_check(CID, {'scope': SCOPE},
                                      facts([change(x, status='Pending' if x == 'b' else 'Succeeded')
                                             for x in order], [activity('b')]))
    assert status == 'FAIL', evidence
    assert change('a')['id'] in evidence['unattributed_changes']
    assert change('b')['id'] in evidence['unresolved_changes']


def test_unresolved_change_only_is_unknown():
    status, evidence = evaluate_check(CID, {'scope': SCOPE},
                                      facts([change('b', status='Pending')], [activity('b')]))
    assert status == 'UNKNOWN', evidence
    assert change('b')['id'] in evidence['unresolved_changes']


def test_partial_activity_inventory_is_global_unknown():
    index = facts([change('a')], [])
    index['collections']['activity_log'][0]['status'] = 'partial'
    status, evidence = evaluate_check(CID, {'scope': SCOPE}, index)
    assert status == 'UNKNOWN', evidence


def test_ambiguous_activity_join_is_global_unknown_with_missing_other_log():
    first = activity('b')
    second = activity('b')
    second['id'] = 'azure-activity://b-two'
    status, evidence = evaluate_check(CID, {'scope': SCOPE},
                                      facts([change('a'), change('b')], [first, second]))
    assert status == 'UNKNOWN', evidence
    assert evidence['reason'] == 'ambiguous production Activity Log join'


def test_incomplete_data_plane_inventory_is_global_unknown_with_missing_log():
    index = facts([change('a')], [])
    index['context']['metadata']['compliance_policy']['sw26'][CID]['dataPlaneChangesComplete'] = False
    status, evidence = evaluate_check(CID, {'scope': SCOPE}, index)
    assert status == 'UNKNOWN', evidence
    assert evidence['reason'] == 'data-plane change inventory incomplete'
    complete = facts([change('a')], [])
    complete['context']['metadata']['compliance_policy']['sw26'][CID]['productionResourceIds'] = [
        RESOURCE, '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/Microsoft.Web/sites/foreign']
    status, evidence = evaluate_check(CID, {'scope': SCOPE}, complete)
    assert status == 'UNKNOWN', evidence
    assert evidence['reason'] == 'foreign production resource policy'
