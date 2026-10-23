"""Collection self-grant must name an existing policy and new exact permission."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
RESOURCE = PROJECT + '/locations/global/collections/c1'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-discoveryengine-collections-setiampolicy-collection-self-grant')


def case(*, writer=True, already=False, collection=True, policy=True,
         viewer=True, record=None):
    role = PROJECT + '/roles/writer'
    permissions = (['discoveryengine.collections.setIamPolicy'] if writer else []) + (
        ['discoveryengine.collections.get'] if already else [])
    row = {'name': RESOURCE, 'iamPolicy': {'bindings': [], 'etag': 'current'},
           '_coverage': {'iamPolicy': {'status': 'collected' if policy else 'denied'}}}
    if not policy:
        row['iamPolicy'] = {'collection_status': 'denied'}
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT,
                                 'bindings': [{'role': role, 'members': [SOURCE]}]
                                 if permissions else []}]),
        ('iam_role', PROJECT, [{'name': role, 'includedPermissions': permissions}]),
        ('iam_role_builtin', PROJECT,
         [{'name': 'roles/discoveryengine.agentspaceViewer',
           'includedPermissions': ['discoveryengine.collections.get']}]
         if viewer else [], 'collected' if viewer else 'empty'),
        ('service_account', PROJECT, [], 'empty'),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('org_policy_effective', PROJECT, [], 'empty'),
        ('group', PROJECT, [], 'empty'),
        ('group_membership', PROJECT, [], 'empty'),
        ('discoveryengine_collection', PROJECT, [row] if collection else [],
         'collected' if collection else 'empty'),
    ]
    if record is not None:
        collections.append(('gcp_resource_self_grant_evidence', PROJECT, [record]))
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def reviewed_record():
    return {'TechniqueId': ENTRY['id'], 'SourceId': SOURCE,
            'TargetScope': PROJECT, 'TargetResource': RESOURCE,
            'GrantedResource': RESOURCE,
            'AccessPermission': 'discoveryengine.collections.setIamPolicy',
            'GrantedPrincipalId': SOURCE,
            'GrantedPermissions': ['discoveryengine.collections.get'],
            'PriorPermissionAbsent': True, 'PolicyMutationAuthorized': True,
            'PolicyMutationAccepted': True, 'AfterPermissionAllowed': True,
            'Status': 'verified', 'EvidenceRef': 'reviewed-collection-change'}


def test_existing_collection_with_policy_write_and_grantable_role():
    assert set(case().values()) == {'conditional'}
    assert next(iter(case())).startswith('gcp_verified_authority:possible-discoveryengine-collection-self-grant:')


def test_absent_writer_or_prior_access_has_no_new_gain():
    assert case(writer=False) == {}
    assert case(already=True) == {}


def test_missing_policy_or_role_is_unresolved_not_positive():
    for options in ({'policy': False}, {'viewer': False}):
        assert 'conditional' not in case(**options).values()


def test_reviewed_record_requires_real_same_collection():
    assert any(key.startswith('gcp_verified_authority:self-grant:')
               for key in case(record=reviewed_record()))
    for resource in (PROJECT + '/secrets/s1',
                     RESOURCE + '/dataStores/other',
                     'projects/other/locations/global/collections/c1'):
        record = deepcopy(reviewed_record())
        record['TargetResource'] = resource
        assert not any(key.startswith('gcp_verified_authority:self-grant:')
                       for key in case(record=record))
    child = deepcopy(reviewed_record())
    child['GrantedResource'] += '/dataStores/d1'
    assert not any(key.startswith('gcp_verified_authority:self-grant:')
                   for key in case(record=child))
