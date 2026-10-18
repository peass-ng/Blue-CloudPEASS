# Historical fixture contracts; current native admission is tested separately.
"""Public collection proves configured correlation from approvals and native reads."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from fastapi import HTTPException

from peaso.collectors import azure, collect_live
from peaso.collectors import azure_security_correlation_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from tests.test_peaso_collectors_azurek8s import FakeAzure

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
BASE = SCOPE + '/resourceGroups/rg/providers/'
WORKSPACE = BASE + 'Microsoft.OperationalInsights/workspaces/security'
RULE = BASE + 'Microsoft.Insights/scheduledQueryRules/correlate'
GROUP = BASE + 'Microsoft.Insights/actionGroups/security'
CUSTOMER = '33333333-3333-3333-3333-333333333333'
TABLES = ['SigninLogs', 'AzureActivity', 'AzureNetworkAnalytics_CL']
QUERY = 'SigninLogs | join (AzureActivity) on CorrelationId | join (AzureNetworkAnalytics_CL) on CorrelationId'


def approval():
    now = datetime.now(timezone.utc)
    return {'status': 'collected', 'scope': SCOPE, 'authorized_by': 'security-reviewer',
        'document_id': 'approved-correlation-requirements',
        'observed_at': (now - timedelta(hours=1)).isoformat(),
        'expires_at': (now + timedelta(days=1)).isoformat(),
        'checks': {native.KEY: {
            'requiredWorkspaceIds': [WORKSPACE], 'requiredEventTables': TABLES.copy(),
            'requiredCorrelationFragments': TABLES.copy(), 'maxCorrelationWindowSeconds': 900,
            'ingestionLookbackSeconds': 3600, 'ingestionMaxAgeSeconds': 300,
            'approvedCriteria': [{'operator': 'GreaterThan', 'threshold': 0, 'timeAggregation': 'Count'}],
            'approvedQueryReviews': [{'ruleId': RULE, 'querySha256': hashlib.sha256(QUERY.encode()).hexdigest(),
                                       'correlatedTables': TABLES.copy(), 'approved': True}]}}}


@pytest.mark.parametrize('mode,expected', [
    ('native', 'PASS'), ('readonly_guard', 'PASS'), ('omitted_kind', 'PASS'), ('equals', 'PASS'), ('no_review', 'UNKNOWN'),
    ('disabled', 'FAIL'), ('no_rule', 'FAIL'), ('dangling_action', 'FAIL'),
    ('unapproved', 'FAIL'), ('changed_query', 'UNKNOWN'), ('contradictory_kind', 'UNKNOWN'),
    ('empty_ingestion', 'UNKNOWN'), ('old_ingestion', 'UNKNOWN'), ('partial_logs', 'UNKNOWN'),
    ('denied_logs', 'DENIED'), ('foreign_workspace', 'UNKNOWN'), ('partial_rules', 'UNKNOWN'),
    ('future_ingestion', 'UNKNOWN'), ('bad_columns', 'UNKNOWN')])
def test_normal_hosted_aggregate_collection_and_frozen_engine(monkeypatch, mode, expected):
    review = approval()
    criteria = {'query': QUERY, 'operator': 'GreaterThan', 'threshold': 0, 'timeAggregation': 'Count'}
    rule = {'id': RULE, 'type': 'Microsoft.Insights/scheduledQueryRules', 'kind': 'LogAlert',
        'properties': {'enabled': mode != 'disabled', 'scopes': [WORKSPACE],
            'windowSize': 'PT15M', 'evaluationFrequency': 'PT5M',
            'criteria': {'allOf': [criteria]}, 'actions': {'actionGroups': [GROUP]}}}
    if mode == 'omitted_kind': rule.pop('kind')
    if mode == 'equals':
        criteria['operator'] = 'Equals'
        review['checks'][native.KEY]['approvedCriteria'][0]['operator'] = 'Equals'
    if mode == 'contradictory_kind': rule['properties']['kind'] = 'LogToMetric'
    if mode == 'unapproved': review['checks'][native.KEY]['approvedQueryReviews'][0]['approved'] = False
    if mode == 'changed_query': criteria['query'] += ' | take 1'
    group = {'id': GROUP, 'type': 'Microsoft.Insights/actionGroups', 'properties': {'enabled': True}}
    def response(url, body, audience):
        path = urlsplit(url).path.casefold()
        if mode == 'readonly_guard' and body is not None:
            azure._validate_readonly_post(url, audience, body)
        if body is not None and audience == azure.ARM:
            assert path == '/providers/microsoft.resourcegraph/resources'
            return {'data': [], 'resultTruncated': False}
        if body is not None:
            assert audience == azure.LOGS
            assert path == '/v1/workspaces/' + CUSTOMER + '/query'
            assert set(body) == {'query', 'timespan'}
            assert body['query'].split(' |', 1)[0] in TABLES
            assert '| summarize event_count=count()' in body['query']
            assert 'join' not in body['query'] and 'PRIVATE_SENTINEL' not in body['query']
            if mode == 'denied_logs': raise azure.AzureReadError('fixture_logs_access_denied', 403)
            count = 0 if mode == 'empty_ingestion' else 4
            date = datetime.now(timezone.utc) - timedelta(seconds=600 if mode == 'old_ingestion' else 10)
            if mode == 'future_ingestion': date += timedelta(days=1)
            data = {'tables': [{'name': 'PrimaryResult', 'columns': [
                {'name': 'event_count', 'type': 'long'}, {'name': 'last_ingested_at', 'type': 'datetime'},
                {'name': 'last_event_at', 'type': 'datetime'}],
                'rows': [[count, date.isoformat() if count else None, date.isoformat() if count else None]]}]}
            if mode == 'partial_logs': data['error'] = {'code': 'PartialError', 'message': 'PRIVATE_SENTINEL'}
            if mode == 'bad_columns': data['tables'][0]['columns'][0]['type'] = 'string'
            return data
        assert audience == azure.ARM
        if path == (SCOPE + '/providers/Microsoft.Insights/scheduledQueryRules').casefold():
            value = {'value': [] if mode == 'no_rule' else [deepcopy(rule)]}
            if mode == 'partial_rules': value['nextLink'] = url + '&$skiptoken=next'
            return value
        if path == RULE.casefold(): return deepcopy(rule)
        if path == (SCOPE + '/providers/Microsoft.Insights/actionGroups').casefold():
            return {'value': [] if mode == 'dangling_action' else [deepcopy(group)]}
        if path == GROUP.casefold(): return deepcopy(group)
        if path == WORKSPACE.casefold():
            return {'id': WORKSPACE + '/foreign' if mode == 'foreign_workspace' else WORKSPACE,
                'type': 'Microsoft.OperationalInsights/workspaces', 'properties': {'customerId': CUSTOMER}}
        assert '/providers/microsoft.insights/diagnostic' in path
        return {'value': []}
    transport = FakeAzure(response)
    transport.tenant = transport.verified_tenant = '22222222-2222-2222-2222-222222222222'
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda connector, kinds: original(connector, kinds, transport=transport))
    options = {'retries': 1, 'compliance_policy': {'sw13': review},
               **({'max_pages': 1} if mode == 'partial_rules' else {})}
    if mode == 'no_review': options.pop('compliance_policy')
    auth = {'method': 'token', 'arm_token': 'inert', 'logs_token': 'inert'}
    before = deepcopy(options)
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [native.CID]})
    assert set(requirements) == {'scheduled_query_rule', 'action_group', *native.NATIVE_TYPES}
    snapshot = collect_live(connector, requirements)
    assert options == before
    results = evaluate_snapshot(snapshot, checks=[native.CID])['findings']
    assert len(results) == 1 and results[0]['status'] == expected, results
    assert results[0]['resource_id'] == 'scope:' + SCOPE
    reviews = next(c for c in snapshot['collections'] if c['type'] == 'security_query_review')
    if mode == 'no_review':
        assert reviews['status'] == 'not_collected' and reviews['items'] == []
    else:
        assert reviews['status'] == 'collected'
        assert reviews['items'][0]['_provenance']['authority'] == 'operator_approval'
        assert reviews['items'][0]['_provenance']['cloud_semantics_measured'] is False
    ingestion = next(c for c in snapshot['collections'] if c['type'] == 'security_table_ingestion')
    if mode in {'native', 'omitted_kind', 'equals', 'no_rule'}:
        assert ingestion['status'] == 'collected' and len(ingestion['items']) == 3
        assert all(row['_provenance']['event_payload_retained'] is False for row in ingestion['items'])
    assert 'PRIVATE_SENTINEL' not in str(snapshot)
    assert sum(aud == azure.LOGS for _, _, aud in transport.calls) == (1 if mode in {
        'partial_logs', 'denied_logs', 'future_ingestion', 'bad_columns'} else 0 if mode in {'foreign_workspace', 'no_review'} else 3)


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('mutation', ['table_injection', 'bool_age', 'foreign_workspace', 'observed_ingestion',
                                     'forged_authority', 'duplicate_review', 'bad_hash', 'missing_review',
                                     'encoded_workspace', 'dot_workspace', 'backslash_workspace'])
def test_invalid_or_observed_approval_input_rejected_before_any_read(mode, mutation):
    review = approval(); config = review['checks'][native.KEY]
    if mutation == 'table_injection': config['requiredEventTables'][0] = 'SigninLogs | take 1'
    elif mutation == 'bool_age': config['ingestionMaxAgeSeconds'] = True
    elif mutation == 'foreign_workspace': config['requiredWorkspaceIds'][0] = WORKSPACE.replace('11111111-', '99999999-', 1)
    elif mutation == 'observed_ingestion': config['ingestionConfirmed'] = True
    elif mutation == 'forged_authority': config['approvedQueryReviews'][0]['_provenance'] = {'read_only': True}
    elif mutation == 'duplicate_review': config['approvedQueryReviews'].append(deepcopy(config['approvedQueryReviews'][0]))
    elif mutation == 'bad_hash': config['approvedQueryReviews'][0]['querySha256'] = 'bad'
    elif mutation == 'encoded_workspace': config['requiredWorkspaceIds'][0] = WORKSPACE + '%2Fescape'
    elif mutation == 'dot_workspace': config['requiredWorkspaceIds'][0] = WORKSPACE.rsplit('/', 1)[0] + '/..'
    elif mutation == 'backslash_workspace': config['requiredWorkspaceIds'][0] = WORKSPACE + '\\escape'
    else: config.pop('approvedQueryReviews')
    with pytest.raises(HTTPException) as error:
        validate_connector('azure', {'method': 'token', 'arm_token': 'inert'},
            {'compliance_policy': {'sw13': review}}, SimpleNamespace(auth_mode=mode))
    assert error.value.status_code == 422
