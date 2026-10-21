"""Native ARM activity-alert coverage through collector, index, and current evaluator."""
from copy import deepcopy
from unittest.mock import patch

import pytest
from tests import test_azure_activity_alert_native_review_20261020 as native

ORIGINAL_NATIVE = native.native
OPERATION_SPECS = [spec for spec in native.SPECS
                   if spec['family'] in ('loose', 'strict') and spec['operation']
                   and spec['id'].startswith('azure.claude.')]
assert len([s for s in OPERATION_SPECS if s['family'] == 'loose']) == 10
assert len([s for s in OPERATION_SPECS if s['family'] == 'strict']) == 13


def actual_arm_event(spec):
    row = deepcopy(ORIGINAL_NATIVE(spec))
    # Microsoft documents Resource Manager write/delete events as Administrative.
    for condition in row['properties']['condition']['allOf']:
        if condition.get('field') == 'category':
            condition['equals'] = 'Administrative'
    return row


def capture(spec, transform=lambda row: row, mode='good'):
    def selected(case):
        return transform(actual_arm_event(case))
    with patch.object(native, 'native', selected):
        return native.capture(spec, mode)


@pytest.mark.parametrize('spec', OPERATION_SPECS, ids=lambda spec: spec['id'])
def test_native_positive_and_narrowing(spec):
    assert {row['status'] for row in capture(spec)[2]} == {'PASS'}
    for field, value in [('resourceGroup', 'another'),
                         ('resourceId', '/subscriptions/other/resourceGroups/rg'),
                         ('caller', 'somebody@example.invalid'),
                         ('status', 'Succeeded')]:
        def narrowed(row, field=field, value=value):
            row['properties']['condition']['allOf'].append({'field': field, 'equals': value})
            return row
        assert {r['status'] for r in capture(spec, narrowed)[2]} == {'UNKNOWN'}, (spec['id'], field)
    def wrong_category(row):
        row['properties']['condition']['allOf'][0]['equals'] = 'Security'
        return row
    assert {r['status'] for r in capture(spec, wrong_category)[2]} == {'FAIL'}
    def foreign_scope(row):
        row['properties']['scopes'] = ['/subscriptions/99999999-9999-9999-9999-999999999999']
        return row
    assert {r['status'] for r in capture(spec, foreign_scope)[2]} == {'FAIL'}


@pytest.mark.parametrize('spec', [s for s in OPERATION_SPECS if s['family']=='loose'], ids=lambda spec: spec['id'])
def test_loose_scope_spellings_and_operation_only(spec):
    def slashless(row):
        row['properties']['scopes'] = [native.SCOPE.lstrip('/')]
        return row
    assert {r['status'] for r in capture(spec, slashless)[2]} == {'PASS'}
    def operation_only(row):
        row['properties']['condition']['allOf'] = [c for c in row['properties']['condition']['allOf']
                                                   if c['field']=='operationName']
        return row
    assert {r['status'] for r in capture(spec, operation_only)[2]} == {'PASS'}
    def group_only(row):
        row['properties']['scopes'] = [native.SCOPE + '/resourceGroups/another']
        return row
    assert {r['status'] for r in capture(spec, group_only)[2]} == {'FAIL'}
    def malformed(row):
        row['properties']['scopes'] = 'malformed'
        return row
    assert {r['status'] for r in capture(spec, malformed)[2]} == {'UNKNOWN'}


def test_strict_sql_resource_type_branch_preserved():
    spec = next(s for s in native.SPECS if s['id']=='azure.claude.activity_log_alert_subscription_sql_server')
    assert {r['status'] for r in capture(spec)[2]} == {'PASS'}
    def narrowed(row):
        row['properties']['condition']['allOf'].append({'field': 'resourceGroup', 'equals': 'another'})
        return row
    assert {r['status'] for r in capture(spec, narrowed)[2]} == {'FAIL'}


def test_native_denied_and_partial_without_fabricated_success():
    spec = OPERATION_SPECS[0]
    assert {r['status'] for r in capture(spec, mode='denied')[2]} == {'DENIED'}
    statuses = {r['status'] for r in capture(spec, mode='partial')[2]}
    assert statuses == {'UNKNOWN'}, statuses


@pytest.mark.parametrize('check_id,other_operation', [
    ('azure.claude.activity_log_alert_nsg_delete', 'Microsoft.ClassicNetwork/networkSecurityGroups/delete'),
    ('azure.claude.activity_log_alert_subscription_administrative_operations', 'Microsoft.Network/networkSecurityGroups/write'),
])
def test_distinct_valid_operation_names_are_contradictory(check_id, other_operation):
    spec = next(s for s in OPERATION_SPECS if s['id'] == check_id)
    def second_operation(row):
        row['properties']['condition']['allOf'].append({'field': 'operationName', 'equals': other_operation})
        return row
    assert {r['status'] for r in capture(spec, second_operation)[2]} == {'FAIL'}
    def same_operation(row):
        row['properties']['condition']['allOf'].append({'field': 'operationName', 'equals': spec['operation'].upper()})
        return row
    assert {r['status'] for r in capture(spec, same_operation)[2]} == {'PASS'}
