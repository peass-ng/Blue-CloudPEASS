"""Hosted APIM intent must never contain imported observations or query text."""
import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from peaso.server.validation import validate_connector

SCOPE = '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
SERVICE = SCOPE + '/resourceGroups/security/providers/Microsoft.ApiManagement/service/gateway'
PREFIX = 'azure_api_management_app_http_logs_enabled_'


def policy():
    end = datetime.now(timezone.utc) - timedelta(minutes=1)
    window = {'start': (end-timedelta(hours=1)).isoformat(), 'end': end.isoformat()}
    return {'status': 'collected', 'scope': SCOPE, 'checks': [
        {'status': 'collected', 'check_id': PREFIX+'21c108d', 'resource_id': SERVICE,
         'minimumSamplingPercentage': 10, 'window': window},
        {'status': 'collected', 'check_id': PREFIX+'9b3b56e', 'resource_id': SERVICE,
         'requiredApiIds': [SERVICE+'/apis/application;rev=1']},
        {'status': 'collected', 'check_id': PREFIX+'9ef06db', 'resource_id': SERVICE,
         'window': copy.deepcopy(window)}]}


def validate(value):
    validate_connector('azure', {'method': 'token', 'arm_token': 'fixture'},
                       {'compliance_policy': {'sw24': value}}, SimpleNamespace(auth_mode='cognito'))


def test_real_hosted_intake_accepts_normative_scope_without_mutation():
    value = policy()
    before = copy.deepcopy(value)
    validate(value)
    assert value == before


@pytest.mark.parametrize('mutation', [
    'foreign_service', 'observation', 'query', 'duplicate', 'zero_sampling',
    'bool_sampling', 'foreign_api', 'future', 'too_old', 'naive', 'unknown', 'empty',
    'more_than_native_budget', 'nested_unbounded',
])
def test_hosted_intake_rejects_unapproved_or_unbounded_apim_facts(mutation):
    value = policy()
    row = value['checks'][0]
    if mutation == 'foreign_service':
        row['resource_id'] = row['resource_id'].replace('aaaaaaaa', 'bbbbbbbb')
    elif mutation == 'observation':
        row['receipt_count'] = 42
    elif mutation == 'query':
        row['query'] = 'union *'
    elif mutation == 'duplicate':
        value['checks'].append(copy.deepcopy(row))
    elif mutation == 'zero_sampling':
        row['minimumSamplingPercentage'] = 0
    elif mutation == 'bool_sampling':
        row['minimumSamplingPercentage'] = True
    elif mutation == 'foreign_api':
        value['checks'][1]['requiredApiIds'] = ['https://foreign.test/api']
    elif mutation == 'future':
        row['window']['end'] = (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    elif mutation == 'too_old':
        row['window']['start'] = (datetime.now(timezone.utc)-timedelta(days=40)).isoformat()
    elif mutation == 'naive':
        row['window']['start'] = datetime.now().isoformat()
    elif mutation == 'unknown':
        row['check_id'] = 'foreign.check'
    elif mutation == 'empty':
        row['window'] = {}
    elif mutation == 'more_than_native_budget':
        value['checks'] = [copy.deepcopy(row) for _ in range(65)]
        for n, child in enumerate(value['checks']):
            child['resource_id'] += str(n)
    elif mutation == 'nested_unbounded':
        row['window'] = {'start': ['x']*257, 'end': row['window']['end']}
    with pytest.raises(HTTPException) as error:
        validate(value)
    assert error.value.status_code == 422
