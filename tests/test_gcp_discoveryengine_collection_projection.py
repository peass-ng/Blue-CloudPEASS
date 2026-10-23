"""Collection inventory keeps exact names and policies without corpus payloads."""

import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType

import pytest


_PATH = Path(__file__).resolve().parents[1] / 'peaso/collectors/gcp_discoveryengine_collections.py'
_SPEC = spec_from_file_location('peaso.collectors.gcp_discoveryengine_collections', _PATH)
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
RESOURCE = 'projects/p1/locations/global/collections/c1'


class ReadError(Exception):
    def __init__(self, status, error):
        self.status = status
        self.error = error


@pytest.fixture(autouse=True)
def stub_collector_error(monkeypatch):
    package = ModuleType('peaso.collectors')
    package.__path__ = []
    module = ModuleType('peaso.collectors.gcp')
    module.ReadError = ReadError
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, module.__name__, module)


def test_projection_reads_exact_policy_and_discards_connector_details():
    class Collector:
        def pages(self, url, scope, **kwargs):
            assert scope == 'projects/p1'
            assert kwargs['key'] == 'collections'
            if '/locations/global/' in url:
                yield [kwargs['transform']({'name': RESOURCE,
                                            'dataConnector': {'token': 'discard-me'}})], 'list-global'
            else:
                yield [], 'list-other'

        def hydrate(self, row, field, url, scope):
            assert field == 'iamPolicy'
            assert url == 'https://discoveryengine.googleapis.com/v1alpha/' + RESOURCE + ':getIamPolicy'
            assert scope == 'projects/p1'
            return {**row, 'iamPolicy': {'etag': 'current', 'bindings': []},
                    '_coverage': {'iamPolicy': {'status': 'collected'}}}

        def parallel(self, function, rows):
            return [function(row) for row in rows]

    result = list(_MODULE.collection_pages(Collector(), 'projects/p1'))
    rows = [row for batch, _ in result for row in batch]
    assert rows == [{'name': RESOURCE, '_representation': 'partial',
                     'iamPolicy': {'etag': 'current', 'bindings': []},
                     '_coverage': {'iamPolicy': {'status': 'collected'}}}]
    assert 'discard-me' not in repr(result)


def test_wrong_collection_identity_is_rejected():
    for name in ('projects/p1/secrets/s1',
                 'projects/p2/locations/global/collections/c1',
                 'projects/p1/locations/global/collections/c1/dataStores/d1'):
        with pytest.raises(ReadError):
            _MODULE.project({'name': name}, 'projects/p1', 'global')


def test_numeric_alias_is_crm_bound_and_canonicalized_for_all_child_reads():
    numeric = 'projects/1234/locations/global/collections/c1'
    canonical = 'projects/p1/locations/global/collections/c1'

    class Collector:
        def __init__(self):
            self.bindings = []
            self.urls = []

        def _data_project_binding(self, scope, *, require_alias=False):
            self.bindings.append((scope, require_alias))
            return {'project_id': 'p1', 'project_number': '1234'}

        def pages(self, url, scope, **kwargs):
            self.urls.append(url)
            if kwargs['key'] == 'collections':
                rows = [{'name': numeric}] if '/locations/global/' in url else []
                yield [kwargs['transform'](row) for row in rows], 'collections'
            elif kwargs['key'] == 'dataStores':
                rows = [{'name': numeric + '/dataStores/d1'}] if url.endswith('/collections/c1/dataStores') else []
                yield rows, 'stores'
            elif kwargs['key'] == 'engines':
                yield [{'name': numeric + '/engines/e1'}], 'engines'

        def hydrate(self, row, field, url, scope):
            assert url.startswith('https://discoveryengine.googleapis.com/v1alpha/projects/p1/')
            return row

        def parallel(self, function, rows):
            return [function(row) for row in rows]

    collector = Collector()
    collections = [row for page, _ in _MODULE.collection_pages(collector, 'projects/p1') for row in page]
    stores = [row for page, _ in _MODULE.data_store_pages(collector, 'projects/p1') for row in page]
    engines = [row for page, _ in _MODULE.engine_pages(collector, 'projects/p1') for row in page]
    assert [row['name'] for row in collections] == [canonical]
    assert [row['name'] for row in stores] == [canonical + '/dataStores/d1']
    assert [row['name'] for row in engines] == [canonical + '/engines/e1']
    assert collector.bindings and all(value == ('projects/p1', True) for value in collector.bindings)
    assert all('/projects/1234/' not in url for url in collector.urls)


def test_unproved_numeric_and_foreign_names_stay_rejected():
    class Collector:
        def _data_project_binding(self, scope, *, require_alias=False):
            return {'project_id': 'p1', 'project_number': '1234'}

    for name in ('projects/5678/locations/global/collections/c1',
                 'projects/other/locations/global/collections/c1'):
        with pytest.raises(ReadError):
            _MODULE.project({'name': name}, 'projects/p1', 'global', Collector())


def test_data_store_projection_covers_standalone_and_collection_child():
    standalone = 'projects/p1/locations/global/dataStores/d1'
    child = RESOURCE + '/dataStores/d2'

    class Collector:
        def pages(self, url, scope, **kwargs):
            assert scope == 'projects/p1'
            if kwargs['key'] == 'collections':
                yield ([kwargs['transform']({'name': RESOURCE})]
                       if '/locations/global/' in url else []), 'collections-list'
            elif url.endswith('/locations/global/dataStores'):
                yield [{'name': standalone, 'password': 'discard-me'},
                       {'name': child, 'password': 'discard-me'}], 'standalone-list'
            elif url.endswith('/collections/c1/dataStores'):
                yield [{'name': child, 'password': 'discard-me'}], 'child-list'
            else:
                yield [], 'empty-list'

        def hydrate(self, row, field, url, scope):
            assert url == 'https://discoveryengine.googleapis.com/v1alpha/' + row['name'] + ':getIamPolicy'
            return {**row, field: {'bindings': []},
                    '_coverage': {field: {'status': 'collected'}}}

        def parallel(self, function, rows):
            return [function(row) for row in rows]

    result = list(_MODULE.data_store_pages(Collector(), 'projects/p1'))
    assert [row['name'] for batch, _ in result for row in batch] == [standalone, child]
    assert 'discard-me' not in repr(result)


def test_data_store_parent_mismatch_is_rejected():
    class Collector:
        def pages(self, url, scope, **kwargs):
            if kwargs['key'] == 'collections':
                yield [], None
            elif url.endswith('/locations/global/dataStores'):
                yield [{'name': 'projects/p2/locations/global/dataStores/d1'}], 'wrong-parent'
            else:
                yield [], None

    with pytest.raises(ReadError):
        list(_MODULE.data_store_pages(Collector(), 'projects/p1'))


def test_engine_projection_binds_child_to_its_collection():
    engine = RESOURCE + '/engines/e1'

    class Collector:
        def pages(self, url, scope, **kwargs):
            assert scope == 'projects/p1'
            if kwargs['key'] == 'collections':
                yield ([kwargs['transform']({'name': RESOURCE})]
                       if '/locations/global/' in url else []), 'collections-list'
            elif kwargs['key'] == 'engines':
                assert url.endswith('/collections/c1/engines')
                yield [{'name': engine, 'chatEngineConfig': {'secret': 'discard-me'}}], 'engines-list'

        def hydrate(self, row, field, url, scope):
            assert url == 'https://discoveryengine.googleapis.com/v1alpha/' + engine + ':getIamPolicy'
            return {**row, field: {'bindings': []},
                    '_coverage': {field: {'status': 'collected'}}}

        def parallel(self, function, rows):
            return [function(row) for row in rows]

    result = list(_MODULE.engine_pages(Collector(), 'projects/p1'))
    assert [row['name'] for batch, _ in result for row in batch] == [engine]
    assert 'discard-me' not in repr(result)


def test_engine_wrong_collection_is_rejected():
    class Collector:
        def pages(self, url, scope, **kwargs):
            if kwargs['key'] == 'collections':
                yield ([kwargs['transform']({'name': RESOURCE})]
                       if '/locations/global/' in url else []), None
            elif kwargs['key'] == 'engines':
                yield [{'name': 'projects/p1/locations/global/collections/other/engines/e1'}], 'wrong-parent'

    with pytest.raises(ReadError):
        list(_MODULE.engine_pages(Collector(), 'projects/p1'))
