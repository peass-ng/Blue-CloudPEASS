"""Engine policy control reaches only a new permission on one exact engine."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
COLLECTION = PROJECT + '/locations/global/collections/c1'
ENGINE = COLLECTION + '/engines/e1'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-discoveryengine-engines-setiampolicy-engine-self-grant')


def case(*, writer=True, prior=False, parent_prior=False, policy=True,
         admin_role=True, record=None):
    writer_role = PROJECT + '/roles/policyWriter'
    source_perms = (['discoveryengine.engines.setIamPolicy'] if writer else []) + (
        ['discoveryengine.engines.update'] if prior else [])
    engine = {'name': ENGINE, 'iamPolicy': {'etag': 'current', 'bindings': []},
              '_coverage': {'iamPolicy': {'status': 'collected' if policy else 'denied'}}}
    if not policy:
        engine['iamPolicy'] = {'collection_status': 'denied'}
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT,
                                 'bindings': [{'role': writer_role, 'members': [SOURCE]}]
                                 if source_perms else []}]),
        ('iam_role', PROJECT, [{'name': writer_role,
                               'includedPermissions': source_perms}]),
        ('iam_role_builtin', PROJECT,
         [{'name': 'roles/discoveryengine.agentspaceAdmin',
           'includedPermissions': ['discoveryengine.engines.update']}]
         if admin_role else [], 'collected' if admin_role else 'empty'),
        ('service_account', PROJECT, [], 'empty'),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('org_policy_effective', PROJECT, [], 'empty'),
        ('group', PROJECT, [], 'empty'),
        ('group_membership', PROJECT, [], 'empty'),
        ('discoveryengine_engine', PROJECT, [engine]),
    ]
    if parent_prior:
        parent_role = PROJECT + '/roles/parentUpdater'
        collections.append(('discoveryengine_collection', PROJECT, [{
            'name': COLLECTION,
            'iamPolicy': {'bindings': [{'role': parent_role, 'members': [SOURCE]}]},
            '_coverage': {'iamPolicy': {'status': 'collected'}}}]))
        collections[2][2].append({'name': parent_role,
                                   'includedPermissions': ['discoveryengine.engines.update']})
    if record is not None:
        collections.append(('gcp_resource_self_grant_evidence', PROJECT, [record]))
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def reviewed():
    return {'TechniqueId': ENTRY['id'], 'SourceId': SOURCE,
            'TargetScope': PROJECT, 'TargetResource': ENGINE,
            'GrantedResource': ENGINE,
            'AccessPermission': 'discoveryengine.engines.setIamPolicy',
            'GrantedPrincipalId': SOURCE,
            'GrantedPermissions': ['discoveryengine.engines.update'],
            'PriorPermissionAbsent': True, 'PolicyMutationAuthorized': True,
            'PolicyMutationAccepted': True, 'AfterPermissionAllowed': True,
            'Status': 'verified', 'EvidenceRef': 'reviewed-engine-change'}


def test_exact_engine_with_policy_write_and_grantable_admin_role():
    assert set(case().values()) == {'conditional'}
    assert next(iter(case())).startswith(
        'gcp_verified_authority:possible-discoveryengine-engine-self-grant:')


def test_missing_writer_or_prior_engine_update_is_not_new_access():
    assert case(writer=False) == {}
    assert case(prior=True) == {}
    assert case(parent_prior=True) == {}


def test_incomplete_policy_or_admin_role_is_not_positive():
    assert 'conditional' not in case(policy=False).values()
    assert 'conditional' not in case(admin_role=False).values()


def test_reviewed_record_must_name_same_engine():
    assert any(k.startswith('gcp_verified_authority:self-grant:')
               for k in case(record=reviewed()))
    for invalid in (PROJECT + '/locations/global/engines/e1',
                    COLLECTION + '/dataStores/d1',
                    'projects/other/locations/global/collections/c1/engines/e1'):
        proof = deepcopy(reviewed())
        proof['TargetResource'] = invalid
        assert not any(k.startswith('gcp_verified_authority:self-grant:')
                       for k in case(record=proof))
    child = deepcopy(reviewed())
    child['GrantedResource'] += '/servingConfigs/default'
    assert not any(k.startswith('gcp_verified_authority:self-grant:')
                   for k in case(record=child))
