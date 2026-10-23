"""Data store self-grants must name one store and confer a new update right."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
STANDALONE = PROJECT + '/locations/global/dataStores/d1'
CHILD = PROJECT + '/locations/global/collections/c1/dataStores/d1'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-discoveryengine-datastores-setiampolicy-data-store-self-grant')


def case(*, resource=STANDALONE, writer=True, prior=False, parent_prior=False,
         policy=True, admin_role=True, record=None):
    writer_role = PROJECT + '/roles/policyWriter'
    source_perms = (['discoveryengine.dataStores.setIamPolicy'] if writer else []) + (
        ['discoveryengine.dataStores.update'] if prior else [])
    binds = [{'role': writer_role, 'members': [SOURCE]}] if source_perms else []
    store = {'name': resource, 'iamPolicy': {'etag': 'current', 'bindings': []},
             '_coverage': {'iamPolicy': {'status': 'collected' if policy else 'denied'}}}
    if not policy:
        store['iamPolicy'] = {'collection_status': 'denied'}
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings': binds}]),
        ('iam_role', PROJECT, [{'name': writer_role,
                               'includedPermissions': source_perms}]),
        ('iam_role_builtin', PROJECT,
         [{'name': 'roles/discoveryengine.agentspaceAdmin',
           'includedPermissions': ['discoveryengine.dataStores.update']}]
         if admin_role else [], 'collected' if admin_role else 'empty'),
        ('service_account', PROJECT, [], 'empty'),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('org_policy_effective', PROJECT, [], 'empty'),
        ('group', PROJECT, [], 'empty'),
        ('group_membership', PROJECT, [], 'empty'),
        ('discoveryengine_data_store', PROJECT, [store]),
    ]
    if parent_prior and '/collections/' in resource:
        parent_role = PROJECT + '/roles/parentUpdater'
        collections.append(('discoveryengine_collection', PROJECT, [{
            'name': resource.rsplit('/dataStores/', 1)[0],
            'iamPolicy': {'bindings': [{'role': parent_role, 'members': [SOURCE]}]},
            '_coverage': {'iamPolicy': {'status': 'collected'}}}]))
        collections[2][2].append({'name': parent_role,
                                   'includedPermissions': ['discoveryengine.dataStores.update']})
    if record is not None:
        collections.append(('gcp_resource_self_grant_evidence', PROJECT, [record]))
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def reviewed(resource=STANDALONE):
    return {'TechniqueId': ENTRY['id'], 'SourceId': SOURCE,
            'TargetScope': PROJECT, 'TargetResource': resource,
            'GrantedResource': resource,
            'AccessPermission': 'discoveryengine.dataStores.setIamPolicy',
            'GrantedPrincipalId': SOURCE,
            'GrantedPermissions': ['discoveryengine.dataStores.update'],
            'PriorPermissionAbsent': True, 'PolicyMutationAuthorized': True,
            'PolicyMutationAccepted': True, 'AfterPermissionAllowed': True,
            'Status': 'verified', 'EvidenceRef': 'reviewed-data-store-change'}


def test_standalone_and_child_store_can_gain_update():
    for resource in (STANDALONE, CHILD):
        assert set(case(resource=resource).values()) == {'conditional'}
        assert next(iter(case(resource=resource))).startswith(
            'gcp_verified_authority:possible-discoveryengine-data-store-self-grant:')


def test_no_writer_or_prior_update_is_not_a_new_gain():
    assert case(writer=False) == {}
    assert case(prior=True) == {}
    assert case(resource=CHILD, parent_prior=True) == {}


def test_incomplete_policy_or_missing_admin_role_is_not_positive():
    assert 'conditional' not in case(policy=False).values()
    assert 'conditional' not in case(admin_role=False).values()


def test_reviewed_record_must_name_same_real_store():
    assert any(k.startswith('gcp_verified_authority:self-grant:')
               for k in case(record=reviewed()))
    for invalid in (PROJECT + '/secrets/s1',
                    PROJECT + '/locations/global/collections/c1',
                    'projects/other/locations/global/dataStores/d1'):
        proof = reviewed(invalid)
        assert not any(k.startswith('gcp_verified_authority:self-grant:')
                       for k in case(record=proof))
    child_proof = deepcopy(reviewed())
    child_proof['GrantedResource'] += '/branches/default_branch'
    assert not any(k.startswith('gcp_verified_authority:self-grant:')
                   for k in case(record=child_proof))
