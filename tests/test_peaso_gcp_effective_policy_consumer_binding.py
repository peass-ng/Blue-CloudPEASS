"""Imported policies need their own project identity, not just a scoped wrapper."""
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = 'projects/p-one'
CHECK = 'gcp.storage.public_access_prevention'
CONSTRAINT = 'storage.publicAccessPrevention'
REQUEST_ID = 'crm-read-1'
ALIAS = {'requested_scope': SCOPE, 'project_id': 'p-one',
         'canonical_name': 'projects/1', 'source_operation': 'projects.get',
         'source_request': REQUEST_ID}
TRACE = {'id': REQUEST_ID, 'url': 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE,
         'method': 'GET', 'scope': SCOPE, 'status': 'collected'}


def imported(name, *, alias=None, trace=None):
    policy = {'name': name, 'constraint': CONSTRAINT, 'spec': {'rules': [{'enforce': True}]}}
    if alias is not None:
        policy['project_alias'] = deepcopy(alias)
    bucket = {'name': 'bucket-one', 'iamConfiguration': {'publicAccessPrevention': 'inherited'}}
    collections = [{'type': 'bucket', 'scope': SCOPE, 'status': 'collected', 'items': [bucket]},
                   {'type': 'org_policy_effective', 'scope': SCOPE, 'status': 'collected', 'items': [policy]}]
    return make_snapshot('gcp', [SCOPE], collections,
                         metadata={'source_requests': [] if trace is None else [deepcopy(trace)]})


def status(snapshot):
    rows = [r for r in evaluate_snapshot(snapshot, checks=[CHECK])['findings'] if r['check_id'] == CHECK]
    assert len(rows) == 1
    return rows[0]['status']


@pytest.mark.parametrize('name,alias,trace,expected', [
    (SCOPE + '/policies/' + CONSTRAINT, None, None, 'PASS'),
    ('projects/999/policies/' + CONSTRAINT, None, None, 'UNKNOWN'),
    (SCOPE + '/policies/compute.requireOsLogin', None, None, 'UNKNOWN'),
    ('projects/1/policies/' + CONSTRAINT, None, None, 'UNKNOWN'),
    ('projects/1/policies/' + CONSTRAINT, ALIAS, None, 'UNKNOWN'),
    ('projects/1/policies/' + CONSTRAINT, ALIAS, TRACE, 'PASS'),
    ('projects/1/policies/' + CONSTRAINT, ALIAS, {**TRACE, 'url': 'https://cloudresourcemanager.googleapis.com/v3/projects/foreign'}, 'UNKNOWN'),
    ('projects/1/policies/' + CONSTRAINT, {**ALIAS, 'project_id': 'foreign'}, TRACE, 'UNKNOWN'),
    (SCOPE + '/policies/' + CONSTRAINT, ALIAS, TRACE, 'UNKNOWN'),
])
def test_imported_snapshot_parent_constraint_and_alias_binding(name, alias, trace, expected):
    assert status(imported(name, alias=alias, trace=trace)) == expected


def producer_fixture():
    path = Path(__file__).with_name('test_peaso_gcp_effective_policy_scope.py')
    spec = importlib.util.spec_from_file_location('_gcp_policy_source_fixture', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('parent,expected,alias_read', [
    (SCOPE, 'PASS', False),
    ('projects/1', 'PASS', True),
    ('projects/999', 'UNKNOWN', True),
])
def test_normal_producer_to_engine_preserves_verified_alias(parent, expected, alias_read):
    source = producer_fixture()
    snapshot, collection, transport = source.collect(parent, kinds=('bucket', 'org_policy_effective'))
    assert status(snapshot) == expected
    assert bool(source.project_get_count(transport)) is alias_read
    if parent == 'projects/1':
        row = next(r for r in collection['items'] if r.get('constraint') == CONSTRAINT)
        assert row['project_alias'] == {**ALIAS, 'source_request': row['project_alias']['source_request']}
        assert any(request['id'] == row['project_alias']['source_request']
                   and request['url'] == TRACE['url']
                   for request in snapshot['metadata']['source_requests'])


@pytest.mark.parametrize('parent,expected', [('projects/1', 'PASS'), ('projects/999', 'UNKNOWN')])
def test_normal_oslogin_consumer_uses_same_project_alias_binding(parent, expected):
    source = producer_fixture()
    snapshot, collection, _ = source.collect(parent, kinds=('instance', 'project', 'org_policy_effective'))
    assert source.finding(snapshot, source.OSLOGIN)['status'] == expected
    if parent == 'projects/1':
        policy = next(r for r in collection['items'] if r.get('constraint') == 'compute.requireOsLogin')
        assert policy['project_alias']['canonical_name'] == parent


def test_direct_registered_callback_without_project_context_is_unknown():
    from peaso.checks import CHECKS
    check = next(row for row in CHECKS if row.id == CHECK)
    bucket = {'name': 'bucket-one', 'iamConfiguration': {'publicAccessPrevention': 'inherited'}}
    policy = {'name': SCOPE + '/policies/' + CONSTRAINT, 'constraint': CONSTRAINT,
              'spec': {'rules': [{'enforce': True}]}}
    index = {'collections': {'org_policy_effective': [{'scope': SCOPE, 'status': 'collected'}]},
             'org_policy_effective': [{'data': policy}]}
    assert check.evaluate(bucket, index)[0] == 'UNKNOWN'
