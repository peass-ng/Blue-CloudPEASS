"""Producer inventory joins versions only to their own shared catalog."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import pytest


ORG = 'organizations/123'
CATALOG = 'catalogs/c1'
PRODUCT = CATALOG + '/products/p1'
VERSION = PRODUCT + '/versions/v1'
TARGET = '//cloudresourcemanager.googleapis.com/projects/456'


@pytest.fixture
def module(monkeypatch):
    root = Path(__file__).resolve().parents[1] / 'peaso/collectors'
    package = ModuleType('isolated_privatecatalog_collector')
    package.__path__ = [str(root)]
    gcp = ModuleType(package.__name__ + '.gcp')
    gcp.ReadError = type('ReadError', (Exception,), {})
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, gcp.__name__, gcp)
    name = package.__name__ + '.gcp_privatecatalog_versions'
    spec = importlib.util.spec_from_file_location(name, root / 'gcp_privatecatalog_versions.py')
    result = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, result)
    spec.loader.exec_module(result)
    return result, gcp.ReadError


class Collector:
    needed = {'service_catalog_version'}

    def __init__(self, *, catalog=None, association=None, product=None, version=None, policy=None):
        self.catalog = catalog or {'name': CATALOG, 'parent': '//cloudresourcemanager.googleapis.com/' + ORG}
        self.association = association or {'name': CATALOG + '/associations/a1', 'resource': TARGET}
        self.product = product or {'name': PRODUCT, 'assetType': 'google.deploymentmanager.Template'}
        self.version = version or {'name': VERSION, 'asset': {'mainTemplate': 'main.jinja'}}
        self.policy = policy if policy is not None else {'bindings': []}
        self.urls = []

    def pages(self, url, scope, *, key='items', params=None, single=False):
        assert scope == ORG
        self.urls.append(url)
        if key == 'catalogs':
            assert params == {'parent': '//cloudresourcemanager.googleapis.com/' + ORG}
            yield [self.catalog], 'catalog-request'
        elif single:
            yield [self.policy], 'policy-request'
        else:
            assert url.endswith('/' + key)
            yield [getattr(self, {'associations': 'association', 'products': 'product',
                                  'versions': 'version'}[key])], key + '-request'


def test_collects_exact_shared_deployable_version(module):
    m, _ = module
    collector = Collector()
    fetch = m.scope_jobs(collector, ORG)[0][3]
    rows = [row for page, _ in fetch() for row in page]
    assert rows == [{'name': VERSION, 'product': PRODUCT, 'catalog': CATALOG,
                     'catalogParent': '//cloudresourcemanager.googleapis.com/' + ORG,
                     'catalogIamPolicy': {'bindings': []},
                     'assetType': 'google.deploymentmanager.Template',
                     'validatedAssetPresent': True, 'consumerTargets': [TARGET]}]
    assert collector.urls == [m.HOST + 'catalogs', m.HOST + CATALOG + ':getIamPolicy',
                              m.HOST + CATALOG + '/associations',
                              m.HOST + CATALOG + '/products', m.HOST + PRODUCT + '/versions']


def test_rejects_mismatched_catalog_product_version_and_association(module):
    m, error = module
    variants = (
        {'catalog': {'name': CATALOG, 'parent': '//cloudresourcemanager.googleapis.com/organizations/other'}},
        {'association': {'name': 'catalogs/other/associations/a1', 'resource': TARGET}},
        {'product': {'name': 'catalogs/other/products/p1'}},
        {'version': {'name': 'catalogs/other/products/p1/versions/v1'}},
        {'policy': {'bindings': {}}},
        {'policy': {'bindings': [{'role': 'roles/viewer', 'members': {}}]}},
    )
    for variant in variants:
        with pytest.raises(error):
            list(m.scope_jobs(Collector(**variant), ORG)[0][3]())
