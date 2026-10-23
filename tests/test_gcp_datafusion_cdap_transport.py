"""CDAP reads stay bound to registered Google-owned Data Fusion endpoints."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

SCOPE = 'projects/example-project'
BASE = ('https://instance-example-project-dot-usc1.'
        'datafusion.googleusercontent.com/api/v3/namespaces')


@pytest.fixture
def gcp(monkeypatch):
    root = Path(__file__).resolve().parents[1] / 'peaso/collectors'
    package = ModuleType('isolated_datafusion_transport')
    package.__path__ = [str(root)]
    monkeypatch.setitem(sys.modules, package.__name__, package)
    for suffix in ('gcp_dataproc_source_runtime_20261020',
                   'gcp_workbench_source_runtime_20261020',
                   'gcp_dataflow_batch_source_runtime_20261020'):
        module = ModuleType(package.__name__ + '.' + suffix)
        module.KINDS = frozenset()
        module.KIND = ''
        monkeypatch.setitem(sys.modules, module.__name__, module)
    catalog = ModuleType(package.__name__ + '.gcp_network_catalog')
    catalog.TYPES = frozenset()
    catalog.PRIVATE_SERVICES = {}
    catalog.SERVICE_ENDPOINTS = {}
    catalog.REGIONAL = {}
    monkeypatch.setitem(sys.modules, catalog.__name__, catalog)
    extra = ModuleType(package.__name__ + '.gcp_additional_literal_secret_indicators')
    extra.OPERATION = 'unused-operation:'
    extra.should_intercept = lambda *args: False
    extra.scheduler_endpoint = lambda *args: False
    monkeypatch.setitem(sys.modules, extra.__name__, extra)
    projector = ModuleType(package.__name__ + '.gcp_datafusion_privesc')
    projector.project_cdap_response = lambda data, path: data
    monkeypatch.setitem(sys.modules, projector.__name__, projector)
    access = ModuleType('peaso.ai.access')
    access.bearer = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, access.__name__, access)
    spec = importlib.util.spec_from_file_location(package.__name__ + '.gcp', root / 'gcp.py')
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    spec.loader.exec_module(module)
    return module


def test_cdap_transport_requires_exact_registered_read_and_wraps_list(monkeypatch, gcp):
    calls = []
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization': 'Bearer test'},
                                              close=lambda: None), {}, sleep=lambda _: None)
    session = SimpleNamespace(request=lambda method, url, **kw: (
        calls.append((method, url, kw)) or
        SimpleNamespace(status_code=200, json=lambda: [{'name': 'default'}],
                        headers={}, content=b'[]')),
        close=lambda: None)
    monkeypatch.setattr(transport, '_session', lambda: session)
    try:
        with pytest.raises(gcp.ReadError, match='unsafe_api_endpoint'):
            transport.request('GET', BASE, scope=SCOPE)
        transport.datafusion_cdap_reads[BASE] = (SCOPE, None)
        data, _ = transport.request('GET', BASE, scope=SCOPE)
        assert data == {'items': [{'name': 'default'}]}
        assert len(calls) == 1
        for method, url, scope, body in [
            ('GET', BASE, 'projects/foreign', None),
            ('POST', BASE, SCOPE, None),
            ('GET', BASE.replace('googleusercontent.com', 'example.com'), SCOPE, None),
            ('GET', BASE + '/default/apps/unregistered', SCOPE, None),
            ('GET', BASE, SCOPE, {'request': 'unsafe'}),
        ]:
            with pytest.raises(gcp.ReadError):
                transport.request(method, url, scope=scope, body=body)
        assert len(calls) == 1
    finally:
        transport.close()


def test_registered_plugin_inventory_path_is_bounded_to_canonical_artifact(monkeypatch, gcp):
    calls = []
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization': 'Bearer test'},
                                              close=lambda: None), {}, sleep=lambda _: None)
    session = SimpleNamespace(request=lambda method, url, **kw: (
        calls.append(url) or SimpleNamespace(status_code=200,
                                             json=lambda: [{'name': 'PySparkProgram'}],
                                             headers={}, content=b'[]')),
        close=lambda: None)
    monkeypatch.setattr(transport, '_session', lambda: session)
    url = BASE + '/default/artifacts/cdap-data-pipeline/versions/6.3.0/extensions/action'
    try:
        transport.datafusion_cdap_reads[url] = (SCOPE, {'scope': 'system'})
        result, _ = transport.request('GET', url, scope=SCOPE, params={'scope': 'system'})
        assert result['items'] == [{'name': 'PySparkProgram'}]
        with pytest.raises(gcp.ReadError, match='unsafe_api_endpoint'):
            transport.request('GET', url + '/plugins/other', scope=SCOPE,
                              params={'scope': 'system'})
        assert calls == [url]
    finally:
        transport.close()
