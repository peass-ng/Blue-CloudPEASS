"""The Dataplex task path uses collected lake identity and exact lake IAM."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import pytest


@pytest.fixture
def module(monkeypatch):
    root = Path(__file__).resolve().parents[1] / 'peaso/collectors'
    package = ModuleType('isolated_dataplex_collection')
    package.__path__ = [str(root)]
    gcp = ModuleType(package.__name__ + '.gcp')
    gcp.ReadError = type('ReadError', (Exception,), {})
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, gcp.__name__, gcp)
    name = package.__name__ + '.gcp_dataplex_privesc'
    spec = importlib.util.spec_from_file_location(name, root / 'gcp_dataplex_privesc.py')
    loaded = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, loaded)
    spec.loader.exec_module(loaded)
    return loaded, gcp.ReadError


def test_collects_active_lake_and_its_policy_without_other_lake_fields(module):
    collector_module, _ = module

    class Collector:
        needed = {'dataplex_privesc_lake'}

        def _data_project_binding(self, scope, **kwargs):
            return {'project_id': 'p1', 'project_number': '123'}

        def pages(self, url, scope, **kwargs):
            assert scope == 'projects/p1'
            if url.endswith('/locations'):
                return iter([([{'name': 'projects/p1/locations/us-central1'},
                               {'name': 'projects/p1/locations/global'}], 'locations')])
            assert url.endswith('/locations/us-central1/lakes')
            assert kwargs['key'] == 'lakes'
            return iter([([{'name': 'projects/p1/locations/us-central1/lakes/main',
                            'state': 'ACTIVE', 'serviceAccount': 'discard@p1.iam.gserviceaccount.com'}],
                          'lakes')])

        def hydrate(self, item, field, url, scope, **kwargs):
            assert field == 'iamPolicy'
            assert url.endswith('/lakes/main:getIamPolicy')
            assert kwargs['params'] == {'options.requestedPolicyVersion': 3}
            return {**item, field: {'bindings': []}}

    jobs = collector_module.scope_jobs(Collector(), 'projects/p1')
    rows = [item for page, _ in jobs[0][3]() for item in page]
    assert rows == [{'name': 'projects/p1/locations/us-central1/lakes/main',
                     'state': 'ACTIVE', 'iamPolicy': {'bindings': []}}]


def test_rejects_foreign_lake_and_unreachable_regions(module):
    collector_module, ReadError = module

    class Collector:
        needed = {'dataplex_privesc_lake'}

        def _data_project_binding(self, scope, **kwargs):
            return {'project_id': 'p1', 'project_number': '123'}

        def pages(self, url, scope, **kwargs):
            if url.endswith('/locations'):
                return iter([([{'name': 'projects/p1/locations/us-central1'}], 'locations')])
            return iter([([{'name': 'projects/other/locations/us-central1/lakes/main',
                            'state': 'ACTIVE'}], 'lakes')])

    with pytest.raises(ReadError):
        list(collector_module.scope_jobs(Collector(), 'projects/p1')[0][3]())
    with pytest.raises(ReadError):
        collector_module._complete_page({'unreachableLocations': ['us-central1']})
