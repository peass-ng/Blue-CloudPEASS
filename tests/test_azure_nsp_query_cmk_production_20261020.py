"""Real public planning -> Azure.collect -> authenticated fake native ARM HTTP."""
from copy import deepcopy
import json
import socket
from urllib.error import HTTPError
from urllib.parse import urlsplit, parse_qs

import pytest
from peaso import checks
from peaso.collectors import azure
from peaso.collectors import azure_nsp_query_cmk_runtime_20261020 as runtime
from peaso.checks import azure_nsp_query_cmk_runtime_review_20261020 as consumer
from peaso.engine import collect_snapshot, evaluate_snapshot, plan_collection
from tests.test_azure_nsp_query_cmk_runtime_20261020 import (
    ParentHTTP, TOKEN, TENANT, FOREIGN_TENANT, SCOPE, SUB, OTHER, native,
    nsp_mode, query_mode, NATIVE_CASES, CANARY)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError('network/DNS/auth forbidden')
    for owner, names in ((socket, ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex')),
                         (socket.socket, ('connect', 'connect_ex', 'sendto')), (azure, ('credential_for',))):
        for name in names: monkeypatch.setattr(owner, name, blocked)


def request_for(kinds, scopes=None, options=None):
    return {'connector': {'provider': 'azure', 'scopes': scopes or [SUB],
        'auth': {'method': 'token', 'arm_token': TOKEN, 'tenant_id': TENANT},
        'options': {'concurrency': 1, 'retries': 0, 'max_calls': 100, 'max_resources': 200,
                    'max_pages': 8, 'collection_deadline_seconds': 120, **(options or {})}},
        'checks': [consumer.IDS[native.KINDS.index(kind)] for kind in kinds]}


def capture(monkeypatch, kind=native.NSP_KIND, mode='enforced', options=None):
    http = ParentHTTP();(nsp_mode if kind == native.NSP_KIND else query_mode)(http, mode)
    monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    snapshot = collect_snapshot(request_for([kind], options=options))
    findings = evaluate_snapshot(snapshot, checks=[consumer.IDS[native.KINDS.index(kind)]], include_not_applicable=True)['findings']
    assert CANARY not in json.dumps(snapshot) + json.dumps(findings)
    assert TOKEN not in json.dumps(snapshot)
    assert snapshot['metadata']['calls'] == len(http.calls)
    assert sum(call['path'] == SCOPE for call in http.calls) == 1
    return {f['status'] for f in findings}, snapshot, http


@pytest.mark.parametrize('kind,mode,want', NATIVE_CASES)
def test_public_collect_native_branch(monkeypatch, kind, mode, want, record_property):
    actual, snapshot, http = capture(monkeypatch, kind, mode)
    record_property('actual', ','.join(sorted(actual)))
    assert actual == {want}
    assert {c['type'] for c in snapshot['collections']} == {kind, 'subscription'}
    assert all(c['_provenance']['credential_context_id'] == snapshot['metadata']['credential_context_id']
               for c in snapshot['collections'])
    assert all(call['method'] == 'GET' and call['host'] == 'management.azure.com' for call in http.calls)


@pytest.mark.parametrize('kind', native.KINDS)
def test_named_planner_and_metadata_default_without_content_flags(kind):
    assert set(plan_collection(request_for([kind]))) == {kind, 'subscription'}
    assert set(native.KINDS).issubset(azure._selected({}, None))
    assert azure._selected({}, [kind]) == {kind, 'subscription'}
    assert azure.TYPES.count(kind) == 1


@pytest.mark.parametrize('option', [{'max_calls': 2}, {'max_resources': 1}, {'max_pages': 1}])
def test_public_shared_budget_cannot_prove_clean(monkeypatch, option):
    # A one-page limit is tested against an actual nextLink, not a fake flag.
    mode = 'association_partial' if 'max_pages' in option else 'enforced'
    actual, snapshot, http = capture(monkeypatch, options=option, mode=mode)
    assert actual == {'UNKNOWN'}
    assert snapshot['metadata']['calls'] == len(http.calls)
    if 'max_calls' in option: assert len(http.calls) == 2


@pytest.mark.parametrize('mode', ['denied', 'http206', 'duplicate_tenant', 'foreign_id', 'foreign_tenant', 'missing_state', 'disabled'])
def test_native_subscription_untrusted_before_declaration_reads(monkeypatch, mode):
    http = ParentHTTP();body = http.get(SCOPE, runtime.SUBSCRIPTION_VERSION)
    if mode == 'denied': http.put(SCOPE, runtime.SUBSCRIPTION_VERSION, 403)
    if mode == 'http206': http.status = 206
    if mode == 'duplicate_tenant':
        http.put(SCOPE, runtime.SUBSCRIPTION_VERSION, json.dumps(body).replace(
            '"tenantId": "' + TENANT + '"', '"tenantId": "' + FOREIGN_TENANT + '", "tenantId": "' + TENANT + '"').encode())
    if mode == 'foreign_id': body['id'] = SCOPE.replace(SUB, OTHER)
    if mode == 'foreign_tenant': body['tenantId'] = FOREIGN_TENANT
    if mode == 'missing_state': body.pop('state')
    if mode == 'disabled': body['state'] = 'Disabled'
    monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    snapshot = collect_snapshot(request_for(native.KINDS))
    findings = evaluate_snapshot(snapshot, checks=list(consumer.IDS))['findings']
    assert {f['status'] for f in findings} == {'UNKNOWN'}
    assert len(http.calls) == 1
    assert snapshot['metadata'][runtime.METADATA_KEY]['bindings'] == []


@pytest.mark.parametrize('max_calls,want', [(100, 'PASS'), (12, 'UNKNOWN')])
@pytest.mark.parametrize('discovery', [False, True])
def test_nine_subscriptions_no_private_scope_cap_or_budget(monkeypatch, max_calls, want, discovery):
    http = ParentHTTP();template = deepcopy(http.routes);http.routes.clear()
    scopes = ['/subscriptions/' + f'{i:08x}-1111-1111-1111-111111111111' for i in range(1, 10)]
    for scope in scopes:
        sub = scope.rsplit('/', 1)[-1]
        for (path, version, token), body in template.items():
            http.put(path.replace(SUB, sub), version, json.loads(json.dumps(body).replace(SUB, sub)), token)
    if discovery:
        http.put('/subscriptions', runtime.SUBSCRIPTION_VERSION, {'value': [
            http.get(scope, runtime.SUBSCRIPTION_VERSION) for scope in scopes]})
    monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    snapshot = collect_snapshot(request_for([native.NSP_KIND], scopes=['*'] if discovery else scopes,
                                            options={'max_calls': max_calls}))
    report = evaluate_snapshot(snapshot, checks=[consumer.IDS[0]])
    assert {f['status'] for f in report['findings']} == {want}
    assert len([c for c in snapshot['collections'] if c['type'] == native.NSP_KIND]) == 9
    assert len(http.calls) == snapshot['metadata']['calls'] <= max_calls
    assert all(sum(call['path'] == scope for call in http.calls) == 1 for scope in scopes)
    if want == 'PASS': assert len(report['findings']) == 9


def test_joint_check_reuses_subscription_and_account_get(monkeypatch):
    http = ParentHTTP();monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    snapshot = collect_snapshot(request_for(native.KINDS))
    assert {f['status'] for f in evaluate_snapshot(snapshot, checks=list(consumer.IDS))['findings']} == {'PASS'}
    assert len(http.calls) == 9 and sum(c['path'] == SCOPE for c in http.calls) == 1
    assert len({b['capture_id'] for b in snapshot['metadata'][runtime.METADATA_KEY]['bindings']}) == 1


def test_no_kind_preserves_existing_selected_subscription_get(monkeypatch):
    http = ParentHTTP();monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    snapshot = azure.collect(request_for([])['connector'], requirements=['subscription'])
    assert runtime.METADATA_KEY not in snapshot['metadata'] and len(http.calls) == 1
    assert snapshot['collections'][0]['items'][0]['state'] == 'Enabled'
    assert 'adapter' not in snapshot['collections'][0]['items'][0]['_provenance']


def test_subscription_documented_metadata_preserved_for_existing_controls(monkeypatch):
    http = ParentHTTP();body = http.get(SCOPE, runtime.SUBSCRIPTION_VERSION)
    body.update(subscriptionPolicies={'quotaId': 'PayAsYouGo_2014-09-01', 'spendingLimit': 'Off'},
                authorizationSource='RoleBased', managedByTenants=[{'tenantId': FOREIGN_TENANT}])
    monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    snapshot = collect_snapshot(request_for(native.KINDS))
    item = next(c for c in snapshot['collections'] if c['type'] == 'subscription')['items'][0]
    assert item['subscriptionPolicies'] == body['subscriptionPolicies'] and item['authorizationSource'] == 'RoleBased'
    assert item['managedByTenants'] == body['managedByTenants']


@pytest.mark.parametrize('hosted', [False, True])
def test_public_hosted_and_local_use_same_read_only_metadata_path(monkeypatch, hosted):
    actual, snapshot, http = capture(monkeypatch, options={'hosted': hosted})
    assert actual == {'PASS'} and len(http.calls) == 6
    assert not snapshot['metadata'].get('content_secret_scans')


def test_direct_default_metadata_inventory_without_named_check_or_content_optin(monkeypatch):
    http = ParentHTTP();monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    connector = request_for(native.KINDS)['connector']
    connector['options']['inventories'] = list(native.KINDS)
    snapshot = azure.collect(connector)
    assert {f['status'] for f in evaluate_snapshot(snapshot, checks=list(consumer.IDS))['findings']} == {'PASS'}
    assert len(http.calls) == 9
    default_plan = plan_collection({'connector': connector | {'options': {}}})
    assert set(native.KINDS).issubset(default_plan)


@pytest.mark.parametrize('categories,want', [(['Write', 'Delete', 'Action'], 'PASS'), (['Write'], 'FAIL')])
def test_existing_subscription_log_profile_control_keeps_native_subject(monkeypatch, categories, want):
    http = ParentHTTP()
    profile_id = SCOPE + '/providers/Microsoft.Insights/logProfiles/native-profile'
    http.put(SCOPE + '/providers/Microsoft.Insights/logProfiles', '2016-03-01', {'value': [{
        'id': profile_id, 'type': 'Microsoft.Insights/logProfiles', 'name': 'native-profile', 'location': '',
        'properties': {'categories': categories, 'locations': ['eastus'],
                       'serviceBusRuleId': SCOPE + '/resourceGroups/review/providers/Microsoft.ServiceBus/namespaces/native-events/authorizationRules/native-export',
                       'storageAccountId': SCOPE + '/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/storageone'}}]})
    native_open = http.open
    def scoped_http(request, timeout):
        parsed = urlsplit(request.full_url)
        if parsed.path == '/providers/Microsoft.ResourceGraph/resources':
            assert request.get_method() == 'POST' and parsed.scheme == 'https' and parsed.netloc == 'management.azure.com'
            assert parse_qs(parsed.query) == {'api-version': ['2022-10-01']}
            assert request.get_header('Authorization') == 'Bearer ' + TOKEN and timeout == 20
            body = json.loads(request.data)
            assert body['subscriptions'] == [SUB] and body['query'].startswith('Resources | project id, type, name, location, tags, identity, properties, subscriptionId, resourceGroup | order by id asc')
            http.calls.append({'method': 'POST', 'host': parsed.netloc, 'path': parsed.path,
                               'api_version': '2022-10-01', 'page': False})
            raise HTTPError(request.full_url, 403, 'Metadata discovery unavailable', {}, None)
        return native_open(request, timeout)
    http.open = scoped_http
    monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    request = request_for(native.KINDS)
    prior_id = 'azure.gap.monitor_log_profile_enabled_for_all_categories'
    request['checks'].append(prior_id)
    snapshot = collect_snapshot(request)
    findings = evaluate_snapshot(snapshot, checks=request['checks'])['findings']
    by_id = {f['check_id']: f['status'] for f in findings}
    assert by_id == {consumer.IDS[0]: 'PASS', consumer.IDS[1]: 'PASS', prior_id: want}
    assert sum(c['path'] == SCOPE for c in http.calls) == 1
