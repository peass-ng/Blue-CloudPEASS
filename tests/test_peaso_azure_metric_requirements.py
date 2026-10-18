"""Customer metric requirements reach native checks through normal connectors."""
from copy import deepcopy

import pytest
from fastapi import HTTPException

from peaso.checks.compliance_new_sw25_facts import SETTINGS_ID, REQUIRED_ID, _policy
from tests.test_peaso_azure_gateway_requirements import SCOPE, intake

RESOURCE = SCOPE + '/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account'
GROUP = SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/security'


def settings():
    return {'scopes': [RESOURCE], 'severity': 2, 'evaluationFrequency': 'PT1M', 'windowSize': 'PT5M',
            'criteria': {'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria',
                         'allOf': [{'criterionType': 'StaticThresholdCriterion', 'metricNamespace': 'Microsoft.Storage/storageAccounts',
                                    'metricName': 'Transactions', 'timeAggregation': 'Total', 'operator': 'GreaterThan',
                                    'threshold': 5, 'dimensions': []}]}, 'actionGroupIds': [GROUP]}


def approval(cid=SETTINGS_ID):
    criterion = ({'expectedMetricSettings': [settings()]} if cid == SETTINGS_ID else
                 {'requiredMetrics': [{'resourceId': RESOURCE, 'metricName': 'Transactions'}]})
    return {'status': 'collected', 'scope': SCOPE, 'checks': {cid: criterion}}


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('cid', [SETTINGS_ID, REQUIRED_ID])
def test_normal_metric_requirements_reach_shared_bridge(mode, cid):
    value = approval(cid)
    intake(value, mode)
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
                         'metadata': {'compliance_policy': {'sw25': value}}}}
    assert _policy(index, cid) == {**value['checks'][cid], 'scope': SCOPE}


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('mutation', ['foreign_scope', 'zero_interval', 'invalid_severity',
                                    'observed_result', 'boolean_threshold', 'empty_conditions', 'foreign_group'])
def test_invalid_metric_settings_are_rejected_before_collection(mode, mutation):
    value = approval()
    setting = value['checks'][SETTINGS_ID]['expectedMetricSettings'][0]
    if mutation == 'foreign_scope': setting['scopes'] = [RESOURCE.replace('11111111-', '33333333-', 1)]
    if mutation == 'zero_interval': setting['evaluationFrequency'] = 'PT0S'
    if mutation == 'invalid_severity': setting['severity'] = 5
    if mutation == 'observed_result': setting['matched'] = True
    if mutation == 'boolean_threshold': setting['criteria']['allOf'][0]['threshold'] = True
    if mutation == 'empty_conditions': setting['criteria']['allOf'] = []
    if mutation == 'foreign_group': setting['actionGroupIds'] = [GROUP.replace('11111111-', '33333333-', 1)]
    with pytest.raises(HTTPException) as error: intake(value, mode)
    assert error.value.status_code == 422


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('mutation', ['foreign_resource', 'observed_outcome', 'invalid_name'])
def test_required_metric_inputs_cannot_inject_observations(mode, mutation):
    value = approval(REQUIRED_ID)
    requirement = value['checks'][REQUIRED_ID]['requiredMetrics'][0]
    if mutation == 'foreign_resource': requirement['resourceId'] = RESOURCE.replace('11111111-', '33333333-', 1)
    if mutation == 'observed_outcome': requirement['alertFound'] = True
    if mutation == 'invalid_name': requirement['metricName'] = ''
    with pytest.raises(HTTPException) as error: intake(value, mode)
    assert error.value.status_code == 422


def test_empty_required_metric_roster_is_an_explicit_normative_choice():
    value = approval(REQUIRED_ID)
    value['checks'][REQUIRED_ID]['requiredMetrics'] = []
    intake(value)


def test_both_metric_controls_share_one_owner_policy():
    value = approval()
    value['checks'].update(deepcopy(approval(REQUIRED_ID)['checks']))
    intake(value)
