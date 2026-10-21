"""Offline native selected-slot package tests after reviewed source admission."""
import json
from copy import deepcopy
from types import SimpleNamespace
import socket
import pytest

from peaso.collectors import azure
from peaso.collectors import azure_selected_storage_secret_indicators as storage
from peaso.collectors import azure_function_package_source_20261020 as source
from tests import test_azure_function_package_source_20261020 as native
SLOT = native.SITE + '/slots/staging'

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network or credential accessed')
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)


def capture(monkeypatch, *, hosting='function', mutation=None, hit=False, enabled=True, partial=False):
    target = native.target()
    target['site_resource_id'] = SLOT
    options = {'content_secret_scans': enabled, source.OPTION: [target]}
    before_options = deepcopy(options)
    host, route = storage.data_route(target['blob'])
    url = 'https://' + host + route + '&sv=2023-11-03&sp=r&sig=' + native.SAS
    trace = SimpleNamespace(calls=[])
    class Transport:
        tenant = native.TENANT
        verified_tenant = native.TENANT
        def token(self, audience):
            return native.jwt(audience)
        def request(self, *args, **kwargs):
            raise AssertionError('generic transport accessed')
    class Connection:
        sock = None
        def __init__(self, origin, timeout):
            assert origin in ('management.azure.com', host) and 0 < timeout <= 10
            self.origin = origin
        def set_debuglevel(self, level):
            assert level == 0
        def request(self, method, path, body=None, headers=None):
            assert body is None and headers['Authorization'].startswith('Bearer ey')
            assert native.SAS not in path
            if self.origin == 'management.azure.com':
                if path == native.SCOPE + '?api-version=' + storage.SUB_VERSION:
                    op = 'subscription'
                    data = {'id': native.SCOPE, 'subscriptionId': native.SCOPE.rsplit('/',1)[1], 'tenantId': native.TENANT, 'state': 'Enabled'}
                elif path == native.ACCOUNT + '?api-version=' + storage.ARM_VERSION:
                    op = 'account'
                    data = {'id': native.ACCOUNT, 'name': 'sourceaccount', 'type': 'Microsoft.Storage/storageAccounts', 'properties': {'provisioningState':'Succeeded', 'primaryEndpoints':{'blob':'https://' + host + '/'}}}
                elif path == SLOT + '?api-version=' + source.SITE_VERSION:
                    op = 'site_after' if 'site_before' in trace.calls else 'site_before'
                    data = {'id': SLOT, 'name': 'selected-function/staging', 'type': 'Microsoft.Web/sites/slots', 'kind': 'functionapp' if hosting == 'function' else 'app', 'properties': {'reserved': False, 'siteConfig': {'windowsFxVersion': ''}}}
                    if mutation == 'foreign_slot': data['id'] = native.SITE + '/slots/foreign'
                    if mutation == 'parent_fallback': data['id'], data['name'], data['type'] = native.SITE, 'selected-function', 'Microsoft.Web/sites'
                    if mutation == 'wrong_type': data['type'] = 'Microsoft.Web/sites'
                    if mutation == 'changed_site' and op == 'site_after': data['properties']['siteConfig']['windowsFxVersion'] = 'changed'
                elif path == SLOT + '/config/appsettings/list?api-version=' + source.SITE_VERSION:
                    assert method == 'POST'
                    op = 'settings_after' if 'settings_before' in trace.calls else 'settings_before'
                    data = {'id': SLOT + '/config/appsettings', 'name': 'appsettings', 'type': 'Microsoft.Web/sites/slots/config', 'properties': {'WEBSITE_RUN_FROM_PACKAGE': url, 'UNRELATED_SECRET': native.SECRET}}
                    if mutation == 'parent_settings': data['id'], data['type'] = native.SITE + '/config/appsettings', 'Microsoft.Web/sites/config'
                    if mutation == 'stale_pointer': data['properties']['WEBSITE_RUN_FROM_PACKAGE'] = url.replace('function.zip', 'old.zip')
                    if mutation == 'changed_pointer' and op == 'settings_after': data['properties']['WEBSITE_RUN_FROM_PACKAGE'] = url.replace('function.zip', 'old.zip')
                else:
                    raise AssertionError('unexpected ARM path')
                response = native.Response(data)
                if mutation == 'denied' and op == 'settings_before': response.status = 403
                if mutation == 'redirect' and op == 'settings_before': response.status = 302
            else:
                assert path == route
                if method == 'HEAD': op = 'properties_after' if 'properties_before' in trace.calls else 'properties_before'
                else: op = 'content'
                props = {'Content-Type': 'application/zip', 'ETag': '"0x123ABC"', 'x-ms-version': storage.DATA_VERSION, 'x-ms-blob-type': 'BlockBlob', 'x-ms-version-id': native.VERSION}
                if mutation == 'changed_blob' and op == 'properties_after': props['ETag'] = '"0x123ABD"'
                response = native.Response(native.package(hit, ('nested.zip', b'PKbad') if partial else None), headers=props, head=method == 'HEAD')
            trace.calls.append(op)
            self.response = response
        def getresponse(self):
            return self.response
        def close(self):
            pass
    monkeypatch.setattr(source.http.client, 'HTTPSConnection', Connection)
    reader = azure._Reader({'retries':0})
    result = source.collect(reader, Transport(), [native.SCOPE], options, [source.CHECK] if enabled else [], customer_context_id='customer-context', credential_context_id='credential-context')
    assert options == before_options
    return result, trace

@pytest.mark.parametrize('hosting', ['function', 'app_service'])
@pytest.mark.parametrize('hit', [False, True])
def test_slot_positive(monkeypatch, hosting, hit):
    result, trace = capture(monkeypatch, hosting=hosting, hit=hit)
    assert result['results'][0]['reason'] == 'complete'
    assert result['results'][0]['hosting'] == hosting
    assert result['results'][0]['complete'] is True
    assert trace.calls == list(source.OPERATIONS)
    assert source.authentic(result)
    assert bool(result['results'][0]['leaks']) is hit
    assert native.SAS not in json.dumps(result)
    assert native.SECRET not in json.dumps(result)

@pytest.mark.parametrize('mutation,reason', [('foreign_slot','unsupported_hosting'),('parent_fallback','unsupported_hosting'),('wrong_type','unsupported_hosting'),('parent_settings','settings_unbound'),('stale_pointer','package_selection_mismatch'),('denied','native_unavailable'),('redirect','native_unavailable'),('changed_blob','source_version_changed'),('changed_pointer','package_selection_mismatch'),('changed_site','package_reference_changed')])
def test_slot_negative(monkeypatch, mutation, reason):
    result, trace = capture(monkeypatch, mutation=mutation)
    assert result['results'][0]['reason'] == reason
    assert result['results'][0]['complete'] is False
    assert result['results'][0]['leaks'] == []
    assert native.SAS not in json.dumps(result)
    assert native.SECRET not in json.dumps(result)


def test_disabled_zero_io(monkeypatch):
    result, trace = capture(monkeypatch, enabled=False)
    assert result is None
    assert trace.calls == []

@pytest.mark.parametrize('hosting', ['function', 'app_service'])
def test_existing_site_path(monkeypatch, hosting):
    monkeypatch.setattr(native, 'source', source)
    result, trace = native.capture(monkeypatch, hosting=hosting)
    assert result['results'][0]['reason'] == 'complete'
    assert result['results'][0]['hosting'] == hosting
    assert [c[0] for c in trace.calls] == list(source.OPERATIONS)

@pytest.mark.parametrize('hit,expected', [(False, 'PASS'), (True, 'FAIL')])
def test_existing_same_process_consumer_slot(monkeypatch, hit, expected):
    from peaso.checks import azure_function_package_source_20261020 as consumer
    result, _ = capture(monkeypatch, hit=hit)
    status, evidence = consumer.evaluate(result, source.identity({'site_resource_id': SLOT, 'blob': native.target()['blob']}),
        scope=native.SCOPE, expected_selection=result['selection'][native.SCOPE], expected_capture=result['capture'],
        customer_context_id='customer-context', credential_context_id='credential-context', tenant_id=native.TENANT)
    assert status == expected
    assert evidence['runtime_bytes'] == 'unknown'


def test_existing_same_process_consumer_rejects_unbound_slot(monkeypatch):
    from peaso.checks import azure_function_package_source_20261020 as consumer
    result, _ = capture(monkeypatch, mutation='parent_settings')
    status, evidence = consumer.evaluate(result, source.identity({'site_resource_id': SLOT, 'blob': native.target()['blob']}),
        scope=native.SCOPE, expected_selection=result['selection'][native.SCOPE], expected_capture=result['capture'],
        customer_context_id='customer-context', credential_context_id='credential-context', tenant_id=native.TENANT)
    assert status == 'UNKNOWN'


def test_slot_partial_confirmed_leak_stays_fail(monkeypatch):
    from peaso.checks import azure_function_package_source_20261020 as consumer
    result, _ = capture(monkeypatch, hit=True, partial=True)
    marker = result['results'][0]
    assert marker['complete'] is False
    assert marker['leaks']
    status, evidence = consumer.evaluate(result, source.identity({'site_resource_id': SLOT, 'blob': native.target()['blob']}),
        scope=native.SCOPE, expected_selection=result['selection'][native.SCOPE], expected_capture=result['capture'],
        customer_context_id='customer-context', credential_context_id='credential-context', tenant_id=native.TENANT)
    assert status == 'FAIL'
    assert evidence['complete'] is False
    assert evidence['secret_leaks']


def test_slot_portable_projection(monkeypatch):
    from peaso.collectors import azure_function_package_portable_20261020 as exporter
    monkeypatch.setattr(exporter, 'source', source)
    result, _ = capture(monkeypatch)
    target = {'site_resource_id': SLOT, 'blob': native.target()['blob']}
    context = exporter.build_expected_context([target], [native.SCOPE], capture=result['capture'],
        customer_context_id='customer-context', credential_context_id='credential-context',
        tenant_id=native.TENANT, principal_id=native.PRINCIPAL)
    snapshot = exporter.export_native_projection(result, expected_index_context=context)
    assert snapshot['collections'][0]['items'][0]['complete'] is True
    assert snapshot['collections'][0]['items'][0]['identity'] == source.identity(target)
