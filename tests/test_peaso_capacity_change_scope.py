"""Capacity change evidence must remain bound to the approved workload scope."""
import pytest
from peaso.checks import evaluate_check
from tests.compliance_draft_isolation import staged_registry

with staged_registry(('compliance_new_sw25',)):
    from test_peaso_compliance_new_sw25 import fixture, replace_rows, unsafe, RESOURCE, SCOPE, sw


def verdict(change, *, breached=False):
    facts = fixture(sw.CAPACITY_ID)
    if breached:
        unsafe(sw.CAPACITY_ID, facts)
    replace_rows(facts, 'capacity_change_record', [change])
    return evaluate_check(sw.CAPACITY_ID, {'scope': SCOPE}, facts)


@pytest.mark.parametrize('target', ['foreign_subscription', 'unapproved_component', 'missing'])
def test_change_resource_binding_is_global_even_without_breach(target):
    change = {'id': 'change', 'resourceId': RESOURCE, 'forecastId': 'previous-forecast'}
    if target == 'foreign_subscription':
        change['resourceId'] = RESOURCE.replace('/subscriptions/sub/', '/subscriptions/other/')
    elif target == 'unapproved_component':
        change['resourceId'] = RESOURCE + '-other'
    else:
        change.pop('resourceId')
    status, evidence = verdict(change)
    assert status == 'UNKNOWN', (target, status, evidence)


def test_prior_forecast_change_for_approved_component_remains_permitted():
    assert verdict({'id': 'change', 'resourceId': RESOURCE, 'forecastId': 'previous-forecast'})[0] == 'PASS'


def test_global_unapproved_component_cannot_be_overridden_by_known_breach():
    status, evidence = verdict({'id': 'change', 'resourceId': RESOURCE + '-other',
                               'forecastId': 'previous-forecast'}, breached=True)
    assert status == 'UNKNOWN', (status, evidence)
