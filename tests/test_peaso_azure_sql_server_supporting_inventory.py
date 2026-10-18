"""ARM SQL inventory supplies metadata, never credential-test assertions."""
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure, collect_live
from peaso.collectors import bulk_evidence
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from peaso.snapshot import make_snapshot
from tests.test_peaso_collectors_azurek8s import FakeAzure

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
SERVER = SCOPE + '/resourceGroups/rg/providers/Microsoft.Sql/servers/sqlserver'
CID = 'azure.other.database_default_login_restricted'


@pytest.mark.parametrize('mode,expected', [('native', 'UNKNOWN'), ('entra_only', 'UNKNOWN'),
    ('injected_assessment', 'UNKNOWN'), ('denied', 'DENIED'), ('partial', 'UNKNOWN')])
def test_normal_hosted_sql_inventory_without_any_authentication_probe(monkeypatch, mode, expected):
    row = {'id': SERVER, 'type': 'Microsoft.Sql/servers', 'name': 'sqlserver',
           'properties': {'fullyQualifiedDomainName': 'sqlserver.database.windows.net'}}
    if mode == 'entra_only': row['properties']['administrators'] = {'azureADOnlyAuthentication': True}
    if mode == 'injected_assessment': row['defaultCredentialAssessment'] = {'status': 'collected', 'tests': []}
    calls = []
    def response(url, body, audience):
        assert body is None and audience == azure.ARM
        calls.append(url)
        if '/providers/Microsoft.Sql/servers?' in url:
            if mode == 'denied': raise azure.AzureReadError('fixture_access_denied', 403)
            result = {'value': [deepcopy(row)]}
            if mode == 'partial': result['nextLink'] = url + '&$skiptoken=next'
            return result
        if urlsplit(url).path.casefold() == SERVER.casefold(): return deepcopy(row)
        raise AssertionError('unexpected API read: ' + url)
    transport = FakeAzure(response)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda connector, kinds: original(connector, kinds, transport=transport))
    auth = {'method': 'token', 'arm_token': 'inert'}
    options = {'retries': 1, **({'max_pages': 1} if mode == 'partial' else {})}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CID]})
    assert set(requirements) == {'database_server'}
    snapshot = collect_live(connector, requirements)
    source = next(c for c in snapshot['collections'] if c['type'] == 'sql_server')
    alias = next(c for c in snapshot['collections'] if c['type'] == 'database_server')
    assert alias['source_inventory'] == 'sql_server' and alias['status'] == source['status']
    assert source['status'] == ('denied' if mode == 'denied' else 'partial' if mode == 'partial' else 'collected')
    assert len(alias['items']) == (0 if mode == 'denied' else 1)
    if alias['items']:
        metadata = alias['items'][0]
        assert metadata['id'] == SERVER
        assert metadata['properties']['fullyQualifiedDomainName'] == 'sqlserver.database.windows.net'
        assert 'defaultCredentialAssessment' not in metadata
        assert metadata['_coverage']['defaultCredentialAssessment']['status'] == 'not_collected'
    findings = evaluate_snapshot(snapshot, checks=[CID])['findings']
    assert findings and {finding['status'] for finding in findings} == {expected}
    assert calls and all('/providers/Microsoft.Sql/servers' in url for url in calls)
    assert all('database.windows.net' not in url for url in calls)


def test_alias_does_not_mutate_the_original_sql_inventory():
    row = {'id': SERVER, 'properties': {}, 'defaultCredentialAssessment': {'status': 'collected'}}
    original = make_snapshot('azure', [SCOPE], [{'type': 'sql_server', 'scope': SCOPE,
        'status': 'collected', 'items': [row]}])
    before = deepcopy(original)
    class Provider:
        TYPES = {'sql_server'}
        def collect(self, connector, requirements):
            assert requirements == ['sql_server']
            return original
    snapshot = bulk_evidence.collect(Provider(), {'provider': 'azure', 'options': {}}, ['database_server'])
    assert original == before
    source = next(c for c in snapshot['collections'] if c['type'] == 'sql_server')
    assert source['items'][0]['defaultCredentialAssessment'] == {'status': 'collected'}
    alias = next(c for c in snapshot['collections'] if c['type'] == 'database_server')
    assert 'defaultCredentialAssessment' not in alias['items'][0]
