"""Actual registered Azure runtime producer with synthetic read-only ARM transport."""
from copy import deepcopy
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure
from peaso import engine

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
SITE = SCOPE + '/resourceGroups/sample/providers/Microsoft.Web/sites/sample'
CHECK = 'azure.review.app_service.runtime_support_declared'


class Transport:
    def __init__(self, *, deprecated=False, unknown=False):
        self.calls = []
        self.deprecated = deprecated
        self.unknown = unknown
        self.tokens = {}

    def request(self, url, *, body=None, audience=None, max_response_bytes=None):
        assert body is None
        self.calls.append((url, max_response_bytes))
        path = urlsplit(url).path
        site = {'id': SITE, 'name': 'sample', 'type': 'Microsoft.Web/sites',
                'kind': 'app,linux', 'location': 'westeurope', 'properties': {'reserved': True}}
        if path.casefold() == (SCOPE + '/providers/Microsoft.Web/sites').casefold():
            return {'value': [site]}
        if path.casefold() == SITE.casefold():
            return site
        if path.casefold() == (SITE + '/config/web').casefold():
            return {'id': SITE + '/config/web', 'type': 'Microsoft.Web/sites/config',
                    'properties': {'linuxFxVersion': 'PYTHON|3.10' if not self.unknown else 'unresolved'}}
        if path.casefold() == '/providers/microsoft.web/locations/westeurope/webappstacks':
            return {'value': [{'id': '/providers/Microsoft.Web/locations/webAppStacks/python',
                    'name': 'python', 'type': 'Microsoft.Web/locations/webAppStacks', 'location': 'westeurope',
                    'properties': {'majorVersions': [{'minorVersions': [{'stackSettings': {
                    'linuxRuntimeSettings': {'runtimeVersion': 'PYTHON|3.10', 'isDeprecated': self.deprecated}}}]}]}}]}
        return {'value': []}


def run(selected, **kwargs):
    transport = Transport(**kwargs)
    options = {'concurrency': 1, 'max_calls': 60, 'retries': 0}
    if selected:
        options['_azure_app_service_runtime_checks'] = [CHECK]
    connector = {'provider': 'azure', 'scopes': [SCOPE], 'auth': {}, 'options': options}
    original = deepcopy(connector)
    snapshot = azure.collect(connector, ['app_service'], transport=transport)
    assert connector == original
    rows = [c for c in snapshot['collections'] if c['type'] == 'app_service' and c['items']]
    assert rows, [(c['type'], c['status']) for c in snapshot['collections']]
    return rows[0]['items'][0], transport.calls, snapshot


@pytest.mark.parametrize('deprecated,status', [(False, 'PASS'), (True, 'FAIL')])
def test_selected_actual_collector_producer(deprecated, status):
    row, calls, _ = run(True, deprecated=deprecated)
    marker = row['runtime_support_native']
    assert marker['status'] == status, marker
    assert marker['complete'] is True
    assert len([call for call in calls if call[1] is not None]) == 3
    assert len(marker['source_requests']) == 3


def test_selected_unknown_is_closed():
    row, calls, _ = run(True, unknown=True)
    marker = row['runtime_support_native']
    assert marker['status'] == 'UNKNOWN', marker
    assert marker['complete'] is False
    assert len([call for call in calls if call[1] is not None]) == 2


@pytest.mark.parametrize('deprecated,unknown,status', [
    (False, False, 'PASS'), (True, False, 'FAIL'), (False, True, 'UNKNOWN')])
def test_registered_frozen_engine_evaluator(deprecated, unknown, status):
    row, _, snapshot = run(True, deprecated=deprecated, unknown=unknown)
    before = deepcopy(row)
    findings = engine.evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    matching = [finding for finding in findings if finding.get('native_resource_id') == SITE]
    assert len(matching) == 1, findings
    assert matching[0]['status'] == status
    assert row == before


def test_disabled_adds_no_reads():
    row, disabled_calls, _ = run(False)
    selected_row, selected_calls, _ = run(True)
    assert 'runtime_support_native' not in row
    assert selected_row['runtime_support_native']['status'] == 'PASS'
    assert [url for url, bound in disabled_calls] == [url for url, bound in selected_calls if bound is None]
