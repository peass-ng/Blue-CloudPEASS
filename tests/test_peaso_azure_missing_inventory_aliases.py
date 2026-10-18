"""Missing native inventory names resolve to existing read-only ARM sources."""
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, bulk_evidence, collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from peaso.snapshot import make_snapshot
from tests.test_peaso_collectors_azurek8s import FakeAzure

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
SITE = SCOPE + '/resourceGroups/rg/providers/Microsoft.Web/sites/app'
GROUP = SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/operations'
CID = 'azure.cis.key_vaults_store_secrets'


@pytest.mark.parametrize('mode', ['native', 'injected', 'denied', 'partial', 'empty'])
def test_hosted_web_app_routes_native_inventory_without_fetching_any_secret(monkeypatch, mode):
    row = {'id': SITE, 'type': 'Microsoft.Web/sites', 'name': 'app', 'kind': 'app,linux',
           'properties': {'httpsOnly': True, 'appSettings': [{'name': 'PASSWORD', 'value': 'PRIVATE_SENTINEL'}]}}
    if mode == 'injected':
        row['workloadSecrets'] = {'status': 'collected', 'inventory_complete': True,
                                  'classification_complete': True, 'secrets': []}
    def response(url, body, audience):
        assert audience == azure.ARM
        path = urlsplit(url).path.casefold()
        assert all(word not in path for word in ('appsettings', 'publishingcredentials', '/secrets', '/listkeys'))
        if body is not None:
            assert path == '/providers/microsoft.resourcegraph/resources'
            return {'data': [], 'resultTruncated': False}
        if path == (SCOPE + '/providers/Microsoft.Web/sites').casefold():
            if mode == 'denied': raise azure.AzureReadError('fixture_access_denied', 403)
            result = {'value': [] if mode == 'empty' else [deepcopy(row)]}
            if mode == 'partial': result['nextLink'] = url + '&$skiptoken=next'
            return result
        if path == SITE.casefold(): return deepcopy(row)
        assert path.startswith(SITE.casefold() + '/providers/microsoft.insights/') or path.startswith(SITE.casefold() + '/basicpublishingcredentialspolicies/')
        if '/basicpublishingcredentialspolicies/' in path:
            return {'id': urlsplit(url).path, 'properties': {'allow': False}}
        return {'value': []}
    transport = FakeAzure(response)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda connector, kinds: original(connector, kinds, transport=transport))
    auth = {'method': 'token', 'arm_token': 'inert'}
    options = {'retries': 1, **({'max_pages': 1} if mode == 'partial' else {})}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CID]})
    assert requirements == ['web_app']
    snapshot = collect_live(connector, requirements)
    source = next(c for c in snapshot['collections'] if c['type'] == 'app_service')
    alias = next(c for c in snapshot['collections'] if c['type'] == 'web_app')
    assert alias['source_inventory'] == 'app_service'
    expected_state = {'denied': 'denied', 'partial': 'partial', 'empty': 'empty'}.get(mode, 'collected')
    assert source['status'] == alias['status'] == expected_state
    assert len(alias['items']) == (0 if mode in {'denied', 'empty'} else 1)
    for item in alias['items']:
        assert item['id'] == SITE and item['properties']['httpsOnly'] is True
        assert 'workloadSecrets' not in item
        assert item['_coverage']['workloadSecrets']['status'] == 'not_collected'
    assert 'PRIVATE_SENTINEL' not in str(snapshot)
    findings = evaluate_snapshot(snapshot, checks=[CID])['findings']
    expected = {'denied': 'DENIED', 'empty': 'EMPTY'}.get(mode, 'UNKNOWN')
    assert findings and {f['status'] for f in findings} == {expected}


@pytest.mark.parametrize('state', ['collected', 'partial', 'denied', 'empty'])
def test_action_group_alias_uses_native_dispatch_and_preserves_completeness(monkeypatch, state):
    def response(url, body, audience):
        assert body is None and audience == azure.ARM
        path = urlsplit(url).path.casefold()
        if path == (SCOPE + '/providers/Microsoft.Insights/actionGroups').casefold():
            if state == 'denied': raise azure.AzureReadError('fixture_access_denied', 403)
            result = {'value': [] if state == 'empty' else [{'id': GROUP, 'type': 'Microsoft.Insights/actionGroups',
                       'properties': {'enabled': True}}]}
            if state == 'partial': result['nextLink'] = url + '&$skiptoken=next'
            return result
        assert path == GROUP.casefold()
        return {'id': GROUP, 'type': 'Microsoft.Insights/actionGroups', 'properties': {'enabled': True}}
    transport = FakeAzure(response)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda connector, kinds: original(connector, kinds, transport=transport))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE], 'auth': {'method': 'token', 'arm_token': 'inert'},
                             'options': {'retries': 1, **({'max_pages': 1} if state == 'partial' else {})}},
                            ['monitor_action_group'])
    source = next(c for c in snapshot['collections'] if c['type'] == 'action_group')
    alias = next(c for c in snapshot['collections'] if c['type'] == 'monitor_action_group')
    assert alias['status'] == source['status'] == state
    assert alias['items'] == source['items']
    assert alias['source_inventory'] == 'action_group'


def test_web_app_projection_does_not_modify_source_snapshot():
    original = make_snapshot('azure', [SCOPE], [{'type': 'app_service', 'scope': SCOPE,
        'status': 'collected', 'items': [{'id': SITE, 'workloadSecrets': {'status': 'collected'}}]}])
    before = deepcopy(original)
    class Provider:
        TYPES = {'app_service'}
        def collect(self, connector, requirements):
            assert requirements == ['app_service']
            return original
    snapshot = bulk_evidence.collect(Provider(), {'provider': 'azure', 'options': {}}, ['web_app'])
    assert original == before
    alias = next(c for c in snapshot['collections'] if c['type'] == 'web_app')
    assert 'workloadSecrets' not in alias['items'][0]
