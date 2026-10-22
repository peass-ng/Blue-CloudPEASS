"""Dataform privilege review collects exact creator and repository IAM state."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import pytest


PROJECT = 'projects/p1'
LOCATION = PROJECT + '/locations/us-central1'
REPO = LOCATION + '/repositories/r1'


@pytest.fixture
def module(monkeypatch):
    root = Path(__file__).resolve().parents[1] / 'peaso/collectors'
    package = ModuleType('isolated_dataform_privesc_collector')
    package.__path__ = [str(root)]
    gcp = ModuleType(package.__name__ + '.gcp')
    gcp.ReadError = type('ReadError', (Exception,), {})
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, gcp.__name__, gcp)
    name = package.__name__ + '.gcp_dataform_privesc'
    spec = importlib.util.spec_from_file_location(name, root / 'gcp_dataform_privesc.py')
    result = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, result)
    spec.loader.exec_module(result)
    return result, gcp.ReadError


class Collector:
    needed = {'dataform_privesc_location'}

    def __init__(self, *, location=None, config=None, repository=None, policy=None):
        self.location = location if location is not None else {'name': LOCATION}
        self.config = config if config is not None else {'name': LOCATION + '/config',
                                                        'creatorRoleConfig': {}}
        self.repository = repository if repository is not None else {
            'name': REPO, 'serviceAccount': 'workflow@p1.iam.gserviceaccount.com'}
        self.policy = policy if policy is not None else {'bindings': []}

    def _data_project_binding(self, scope, *, require_alias=False):
        assert scope == PROJECT and require_alias
        return {'project_id': 'p1', 'project_number': '1234'}

    def pages(self, url, scope, *, key='items', single=False, transform=None):
        assert scope == PROJECT
        if key == 'locations':
            yield [self.location], 'locations'
        elif key == 'repositories':
            yield [self.repository], 'repositories'
        elif single and url.endswith('/config'):
            yield [self.config], 'config'
        elif single and url.endswith(':getIamPolicy'):
            yield [transform(self.policy)], 'policy'
        else:
            raise AssertionError(url)


def test_reads_location_config_and_exact_repository_policy(module):
    m, _ = module
    rows = [row for page, _ in m.scope_jobs(Collector(), PROJECT)[0][3]() for row in page]
    assert rows == [{'name': LOCATION, 'creatorRoleConfig': {}, 'enablePrivateWorkspace': None,
                     'repositories': [{
        'name': REPO, 'serviceAccount': 'workflow@p1.iam.gserviceaccount.com',
        'teamFolder': None, 'iamPolicy': {'bindings': []}}]}]


def test_rejects_foreign_identity_and_malformed_creator_or_policy(module):
    m, error = module
    variants = (
        {'location': {'name': 'projects/other/locations/us-central1'}},
        {'config': {'name': LOCATION + '/config', 'creatorRoleConfig': {'disableGrant': 'true'}}},
        {'repository': {'name': 'projects/other/locations/us-central1/repositories/r1'}},
        {'policy': {'bindings': {}}},
    )
    for variant in variants:
        with pytest.raises(error):
            list(m.scope_jobs(Collector(**variant), PROJECT)[0][3]())


def test_verified_numeric_project_alias_is_canonicalized(module):
    m, _ = module
    collector = Collector(
        location={'name': 'projects/1234/locations/us-central1'},
        config={'name': 'projects/1234/locations/us-central1/config'},
        repository={'name': 'projects/1234/locations/us-central1/repositories/r1'})
    rows = [row for page, _ in m.scope_jobs(collector, PROJECT)[0][3]() for row in page]
    assert rows[0]['name'] == LOCATION
    assert rows[0]['repositories'][0]['name'] == REPO
