"""Native declaration projection through the actual signed routing evaluator."""
from copy import deepcopy
import json
import pytest

from peaso.collectors.azure_alert_routing_native import CONTRACTS, project, verify_projection
from peaso.checks.compliance_new_sw25_facts import ROUTING_ID
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
RESOURCE = SCOPE + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
GROUP = SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/group'


def native(kind, groups=True, stateful=True):
    native_type, version = CONTRACTS[kind]
    props = {'enabled': True, 'scopes': [RESOURCE]}
    ids = [GROUP] if groups else []
    props['actions'] = ([{'actionGroupId': group} for group in ids] if kind == 'metric_alert' else
        {'actionGroups': [{'actionGroupId': group} for group in ids] if kind == 'activity_log_alert' else ids})
    if kind != 'activity_log_alert': props['autoMitigate'] = stateful
    return {'id': SCOPE + '/resourceGroups/rg/providers/' + native_type + '/alert', 'type': native_type,
        'properties': props, '_provenance': {'read_only': True}}


def verdict(kind, row):
    collections = [{'type': family, 'scope': SCOPE, 'service': 'Microsoft.Insights',
        'status': 'collected' if family == kind else 'empty', 'items': [row] if family == kind else []}
        for family in CONTRACTS]
    snapshot = make_snapshot('azure', [SCOPE], collections)
    return next(f['status'] for f in evaluate_snapshot(snapshot, checks=[ROUTING_ID])['findings'] if f['check_id'] == ROUTING_ID)


@pytest.mark.parametrize('kind', CONTRACTS)
@pytest.mark.parametrize('groups,expected', [(True, 'PASS'), (False, 'FAIL')])
def test_complete_native_routes_pass_and_empty_routes_fail_without_owner_policy(kind, groups, expected):
    raw = native(kind, groups)
    before = deepcopy(raw)
    row = project(kind, SCOPE, raw, CONTRACTS[kind][1])
    assert raw == before
    verify_projection(kind, SCOPE, row)
    assert verdict(kind, row) == expected
    assert 'No Data' not in row['properties']['_applicableActionStates']


@pytest.mark.parametrize('kind', ['metric_alert', 'scheduled_query_rule'])
@pytest.mark.parametrize('stateful', [True, False])
def test_native_stateful_and_stateless_mapping(kind, stateful):
    row = project(kind, SCOPE, native(kind, stateful=stateful), CONTRACTS[kind][1])
    assert row['properties']['_applicableActionStates'] == (['Activated', 'Resolved'] if stateful else ['Activated'])
    assert verdict(kind, row) == 'PASS'


def test_activity_log_is_always_stateless():
    row = project('activity_log_alert', SCOPE, native('activity_log_alert'), '2020-10-01')
    assert row['properties']['_applicableActionStates'] == ['Activated']


def test_documented_scheduled_query_defaults_are_used_only_when_absent():
    row = native('scheduled_query_rule')
    del row['properties']['autoMitigate']
    projected = project('scheduled_query_rule', SCOPE, row, '2021-08-01')
    assert projected['properties']['_applicableActionStates'] == ['Activated', 'Resolved']
    assert verdict('scheduled_query_rule', projected) == 'PASS'


@pytest.mark.parametrize('mode', ['partial_auto', 'null_auto', 'string_auto', 'missing_actions', 'duplicate_group',
    'foreign_group', 'wrong_type', 'foreign_scope', 'partial_actions', 'untrusted_source', 'partial_source', 'precomputed_states'])
def test_unavailable_or_untrusted_native_declarations_cannot_be_projected(mode):
    row = native('metric_alert')
    props = row['properties']
    if mode == 'partial_auto':
        del props['autoMitigate']
        props['_coverage'] = {'autoMitigate': {'status': 'partial'}}
    elif mode == 'null_auto': props['autoMitigate'] = None
    elif mode == 'string_auto': props['autoMitigate'] = 'true'
    elif mode == 'missing_actions': del props['actions']
    elif mode == 'duplicate_group': props['actions'] *= 2
    elif mode == 'foreign_group': props['actions'][0]['actionGroupId'] = GROUP.replace('1111', '2222')
    elif mode == 'wrong_type': row['type'] = 'Microsoft.Compute/virtualMachines'
    elif mode == 'foreign_scope': props['scopes'] = [RESOURCE.replace('1111', '2222')]
    elif mode == 'partial_actions': props['_coverage'] = {'actions': {'status': 'partial'}}
    elif mode == 'untrusted_source': row['_provenance']['read_only'] = False
    elif mode == 'partial_source': row['_provenance']['native_response_complete'] = False
    elif mode == 'precomputed_states': props['_applicableActionStates'] = ['No Data']
    with pytest.raises(ValueError): project('metric_alert', SCOPE, row, '2018-03-01')


@pytest.mark.parametrize('mode', ['route', 'state', 'enabled', 'digest', 'method', 'version'])
def test_modified_projection_is_unknown_in_real_engine(mode):
    row = project('metric_alert', SCOPE, native('metric_alert'), '2018-03-01')
    if mode == 'route': row['properties']['actions'][0]['actionGroupId'] += '-other'
    elif mode == 'state': row['properties']['_applicableActionStates'] = ['Activated']
    elif mode == 'enabled': row['properties']['enabled'] = False
    elif mode == 'digest': row['_routing_provenance']['declarationSha256'] = '0' * 64
    elif mode == 'method': row['_routing_provenance']['method'] = 'POST'
    elif mode == 'version': row['_routing_provenance']['api_version'] = '2099-01-01'
    assert verdict('metric_alert', row) == 'UNKNOWN'


def test_query_and_payload_details_are_not_copied_into_native_proof_or_needed_for_binding():
    raw = native('scheduled_query_rule')
    raw['properties'].update(criteria={'query': 'NEVER_COPY_QUERY'}, customProperties={'secret': 'NEVER_COPY_PAYLOAD'})
    row = project('scheduled_query_rule', SCOPE, raw, '2021-08-01')
    assert 'NEVER_COPY' not in json.dumps(row['_routing_provenance'])
    del row['properties']['criteria']
    del row['properties']['customProperties']
    assert verdict('scheduled_query_rule', row) == 'PASS'


def test_unpinned_api_version_is_rejected():
    with pytest.raises(ValueError): project('metric_alert', SCOPE, native('metric_alert'), '2024-03-01-preview')


def test_scheduled_log_to_metric_is_not_misclassified_as_an_alert():
    row = native('scheduled_query_rule')
    row['kind'] = 'LogToMetric'
    with pytest.raises(ValueError): project('scheduled_query_rule', SCOPE, row, '2021-08-01')
