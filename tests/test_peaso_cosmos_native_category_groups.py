"""Native allLogs routing uses measured category membership, not a category key."""
import pytest

from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_bulk_native import Transport, SCOPE, SUB, BASE, parent, routes

ACCOUNT = BASE + 'Microsoft.DocumentDB/databaseAccounts/account'
WORKSPACE = BASE + 'Microsoft.OperationalInsights/workspaces/security'
COSMOS = 'azure_cosmos_account_10_2_1_1_23_e04a63d'
MONGO = 'azure_cosmos_account_10_2_1_1_13_5c115b0'
DIAGNOSTIC = ACCOUNT + '/providers/Microsoft.Insights/diagnosticSettings/security'


def policy():
    return {'status': 'collected', 'scope': SCOPE, 'approved_cosmos_workspaces': [WORKSPACE]}


def status(snapshot, check):
    findings = evaluate_snapshot(snapshot, checks=[check])['findings']
    assert len(findings) == 1
    return findings[0]['status']


@pytest.mark.parametrize('check', [COSMOS, MONGO])
@pytest.mark.parametrize('mode,expected', [('group', 'PASS'), ('nullable_category', 'PASS'),
                                         ('disabled', 'FAIL'), ('unresolved', 'UNKNOWN'),
                                         ('foreign_member', 'UNKNOWN'), ('ambiguous', 'UNKNOWN')])
def test_group_logs_require_exact_native_supported_category_resolution(check, mode, expected):
    category = 'DataPlaneRequests'
    log = {'enabled': mode != 'disabled', 'categoryGroup': 'allLogs', 'resolvedCategories': [category]}
    if mode == 'nullable_category': log['category'] = None
    if mode == 'unresolved': log.pop('resolvedCategories')
    if mode == 'foreign_member': log['resolvedCategories'] = ['ForeignCategory']
    if mode == 'ambiguous': log['category'] = category
    account = parent(ACCOUNT, 'Microsoft.DocumentDB/databaseAccounts', {'capabilities': [{'name': 'EnableMongo'}]})
    account.update(supported_log_categories=[category], diagnosticSettings=[{
        'id': DIAGNOSTIC, 'properties': {'logs': [log], 'workspaceId': WORKSPACE}}],
        _coverage={'diagnosticSettings': {'status': 'collected'}})
    snapshot = make_snapshot('azure', [SCOPE], [
        {'type': 'cosmos_account', 'scope': SCOPE, 'status': 'collected', 'items': [account]},
        {'type': 'mongo_cluster', 'scope': SCOPE, 'status': 'empty', 'items': []},
    ], metadata={'compliance_policy': {'sw32': policy()}})
    assert status(snapshot, check) == expected


@pytest.mark.parametrize('check', [COSMOS, MONGO])
@pytest.mark.parametrize('mode,expected', [('valid', 'PASS'), ('metrics', 'UNKNOWN'),
                                         ('invalid_group', 'UNKNOWN'), ('duplicate', 'UNKNOWN'),
                                         ('foreign_name', 'UNKNOWN'), ('denied', 'UNKNOWN')])
def test_public_native_diagnostic_category_group_projection_reaches_engine(monkeypatch, check, mode, expected):
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    responses = routes('cosmos_account', ACCOUNT, {'capabilities': [{'name': 'EnableMongo'}]})
    responses[DIAGNOSTIC.rsplit('/', 1)[0]] = {'value': [parent(DIAGNOSTIC,
        'Microsoft.Insights/diagnosticSettings', {'logs': [{'enabled': True, 'categoryGroup': 'allLogs'}],
                                               'workspaceId': WORKSPACE})]}
    categories = ACCOUNT + '/providers/Microsoft.Insights/diagnosticSettingsCategories'
    responses[categories] = {'value': [parent(categories + '/DataPlaneRequests',
        'Microsoft.Insights/diagnosticSettingsCategories', {'categoryType': 'Logs', 'categoryGroups': ['allLogs']})]}
    category = responses[categories]['value'][0]
    if mode == 'metrics': category['properties']['categoryType'] = 'Metrics'
    if mode == 'invalid_group': category['properties']['categoryGroups'] = 'allLogs'
    if mode == 'duplicate': responses[categories]['value'].append(dict(category))
    if mode == 'foreign_name': category['name'] = 'AnotherCategory'
    if mode == 'denied': responses[categories] = azure.AzureReadError('denied', 403)

    class ReadOnlyTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            assert body is None
            return super().request(url, body=body, audience=audience)

    transport = ReadOnlyTransport(responses)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, kinds: original(c, kinds, transport=transport))
    options = {'retries': 1, 'compliance_policy': {'sw32': policy()}}
    auth = {'method': 'token', 'arm_token': 'inert-fixture'}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SUB], 'auth': auth, 'options': options},
        ['cosmos_account', 'mongo_cluster', 'diagnostic_category'])
    assert status(snapshot, check) == expected
    assert any('diagnosticSettingsCategories?' in url for url in transport.calls)
