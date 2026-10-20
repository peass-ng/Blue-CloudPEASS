"""Query POSTs are read-only exceptions; unknown POSTs fail before token use."""
import io
import pytest
from peaso.collectors import azure

UUID = '11111111-2222-3333-4444-555555555555'
ARG = azure.ARM + '/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01'
LOG = 'https://api.loganalytics.azure.com/v1/workspaces/' + UUID + '/query'
POLICY = azure.ARM + '/subscriptions/' + UUID + '/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2024-10-01'
ARG_BODY = {'subscriptions': [UUID], 'query': 'Resources | project id', 'options': {'resultFormat': 'objectArray', '$top': 1000}}

@pytest.fixture
def inert(monkeypatch):
    transport = azure.AzureTransport({'method': 'token', 'arm_token': 'INERT_NOT_A_CREDENTIAL'})
    events = []
    def token(audience):
        events.append(('token', audience))
        return 'INERT_NOT_A_CREDENTIAL'
    class Opener:
        def open(self, request, timeout):
            events.append(('http', request.get_method(), request.full_url, request.data))
            response = io.BytesIO(b'{"value": []}')
            response.status = 200
            return response
    monkeypatch.setattr(transport, 'token', token)
    monkeypatch.setattr(azure, 'build_opener', lambda *args: Opener())
    return transport, events

@pytest.mark.parametrize('url,audience,body', [
    (ARG, azure.ARM, ARG_BODY),
    (ARG, azure.ARM, {**ARG_BODY, 'options': {'$skipToken': 'opaque-next-page', '$top': 1000}}),
    (LOG, azure.LOGS, {'query': 'AzureActivity | summarize count()', 'timespan': 'P1D'}),
    (POLICY + '&$filter=resourceType%20eq%20%27Microsoft.Devices%2FprovisioningServices%27', azure.ARM, {}),
    (POLICY + '&$skiptoken=opaque%2Bpage%3D&$top=100', azure.ARM, {}),
])
def test_documented_query_posts_reach_inert_http(inert, url, audience, body):
    transport, events = inert
    assert transport.request(url, audience=audience, body=body) == {'value': []}
    assert events[0] == ('token', audience)
    assert events[1][0:3] == ('http', 'POST', url)

@pytest.mark.parametrize('url,audience,body', [
    (azure.ARM + '/subscriptions/' + UUID + '/providers/Microsoft.PolicyInsights/policyStates/latest/triggerEvaluation?api-version=2024-10-01', azure.ARM, {}),
    (azure.ARM + '/subscriptions/' + UUID + '/resourceGroups/owned/providers/Microsoft.Compute/virtualMachines/vm/start?api-version=2024-03-01', azure.ARM, {}),
    (azure.GRAPH + '/v1.0/users', azure.GRAPH, {'displayName': 'would-create'}),
    (azure.GRAPH + '/v1.0/$batch', azure.GRAPH, {'requests': [{'method': 'DELETE'}]}),
    (ARG + '&api-version=2022-10-01', azure.ARM, ARG_BODY),
    (ARG + '&API-VERSION=2022-10-01', azure.ARM, ARG_BODY),
    (ARG + '&action=delete', azure.ARM, ARG_BODY),
    (ARG.replace('/resources?', '/resources/delete?'), azure.ARM, ARG_BODY),
    (ARG.replace('/resources?', '/resources/?'), azure.ARM, ARG_BODY),
    (ARG.replace('/resources?', '/%72esources?'), azure.ARM, ARG_BODY),
    (ARG.replace('/resources?', '/../resources?'), azure.ARM, ARG_BODY),
    (ARG.replace('ResourceGraph', 'resourcegraph'), azure.ARM, ARG_BODY),
    (ARG.replace('https:', 'http:'), azure.ARM, ARG_BODY),
    (ARG.replace('management.azure.com', 'management.azure.com.evil.invalid'), azure.ARM, ARG_BODY),
    (ARG + '#ignored', azure.ARM, ARG_BODY),
    (ARG, azure.GRAPH, ARG_BODY),
    (ARG, azure.ARM, {'subscriptions': [UUID], 'query': 'Resources', 'delete': True}),
    (ARG, azure.ARM, {'subscriptions': ['foreign-scope'], 'query': 'Resources'}),
    (ARG, azure.ARM, {'subscriptions': [], 'query': 'Resources'}),
    (ARG, azure.ARM, []),
    (ARG, azure.ARM, False),
    (ARG, azure.ARM, ''),
    (LOG + '?method=DELETE', azure.LOGS, {'query': 'AzureActivity'}),
    (LOG.replace(UUID, 'foreign-workspace'), azure.LOGS, {'query': 'AzureActivity'}),
    (LOG, azure.LOGS, {'query': 'AzureActivity', 'requests': [{'method': 'DELETE'}]}),
    (POLICY, azure.ARM, {'triggerEvaluation': True}),
    (POLICY + '&$skiptoken=one&$skipToken=two', azure.ARM, {}),
    (POLICY + '&api-version=', azure.ARM, {}),
    (POLICY + '&broken', azure.ARM, {}),
])
def test_unknown_or_ambiguous_posts_rejected_before_token_and_http(inert, url, audience, body):
    transport, events = inert
    with pytest.raises(azure.AzureReadError):
        transport.request(url, audience=audience, body=body)
    assert events == []

@pytest.mark.parametrize('url,audience', [
    (azure.ARM + '/subscriptions/' + UUID + '/resources?api-version=2021-04-01', azure.ARM),
    (azure.GRAPH + '/v1.0/users?$select=id', azure.GRAPH),
    ('https://owned.vault.azure.net/keys?api-version=7.4', azure.VAULT),
])
def test_existing_origin_validated_get_unchanged(inert, url, audience):
    transport, events = inert
    transport.vault_hosts.add('owned.vault.azure.net')
    assert transport.request(url, audience=audience) == {'value': []}
    assert events[1][0:3] == ('http', 'GET', url)
    assert events[1][3] is None

def test_existing_untrusted_get_rejected_before_token(inert):
    transport, events = inert
    with pytest.raises(azure.AzureReadError, match='untrusted_continuation'):
        transport.request('https://evil.invalid/v1.0/users', audience=azure.GRAPH)
    assert events == []
