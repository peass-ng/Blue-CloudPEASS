"""A deployment policy self-grant must resolve one exact updatable deployment."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
AGENT = '123@cloudservices.gserviceaccount.com'
RUNNER = 'runner@p1.iam.gserviceaccount.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-deploymentmanager-deployments-setiampolicy')


def case(*, policy_read=True, policy_write=True, etag=True, deployment=True,
         agent=True, admin_role=True, denied_update=False, dm_api=True,
         split_deployment=False, existing_update=False):
    bind = lambda role, member: {'role': role, 'members': [member]}
    policy_role = PROJECT + '/roles/policyEditor'
    deputy = PROJECT + '/roles/deputy'
    source_perms = (['deploymentmanager.deployments.getIamPolicy'] if policy_read else []) + (
        ['deploymentmanager.deployments.setIamPolicy'] if policy_write else []) + (
        ['deploymentmanager.deployments.update'] if existing_update else [])
    agent_perms = ['compute.instances.create', 'compute.instances.setServiceAccount',
                   'compute.instances.setMetadata', 'compute.disks.create',
                   'compute.images.useReadOnly', 'compute.subnetworks.use',
                   'compute.subnetworks.useExternalIp', 'iam.serviceAccounts.actAs']
    row = {'name': 'prior-deployment', 'fingerprint': 'current',
           'iamPolicy': {'bindings': [], **({'etag': 'etag123'} if etag else {})},
           '_coverage': {'iamPolicy': {'status': 'collected'}}}
    rows = [row] if deployment else []
    if split_deployment:
        source_perms = []
        row['iamPolicy']['bindings'] = [bind(PROJECT + '/roles/setOnly', SOURCE)]
        rows.append({'name': 'other-deployment', 'fingerprint': 'current2',
                     'iamPolicy': {'etag': 'etag456', 'bindings':
                                   [bind(PROJECT + '/roles/getOnly', SOURCE)]},
                     '_coverage': {'iamPolicy': {'status': 'collected'}}})
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings':
                                 ([bind(policy_role, SOURCE)] if source_perms else []) +
                                 ([bind(deputy, 'serviceAccount:' + AGENT)] if agent else [])}]),
        ('iam_role', PROJECT, [
            {'name': policy_role, 'includedPermissions': source_perms},
            {'name': PROJECT + '/roles/setOnly', 'includedPermissions':
             ['deploymentmanager.deployments.setIamPolicy']},
            {'name': PROJECT + '/roles/getOnly', 'includedPermissions':
             ['deploymentmanager.deployments.getIamPolicy']},
            {'name': deputy, 'includedPermissions': agent_perms},
        ]),
        ('iam_role_builtin', PROJECT, [{'name': 'roles/deploymentmanager.admin',
                                      'includedPermissions':
                                      ['deploymentmanager.deployments.get',
                                       'deploymentmanager.deployments.update']}]
         if admin_role else [], 'collected' if admin_role else 'empty'),
        ('iam_deny_policy', PROJECT, [{'name': PROJECT + '/denyPolicies/block',
                                      'rules': [{'denyRule': {
                                          'deniedPermissions':
                                          ['deploymentmanager.googleapis.com/deployments.update'],
                                          'deniedPrincipals': [SOURCE]}}]}]
         if denied_update else [], 'collected' if denied_update else 'empty'),
        ('service_account', PROJECT, [{'email': RUNNER, 'projectId': 'p1',
                                      'iamPolicy': {'bindings': []}}]),
        ('service_usage', PROJECT, [
            {'name': PROJECT + '/services/deploymentmanager.googleapis.com',
             'state': 'ENABLED' if dm_api else 'DISABLED'},
            {'name': PROJECT + '/services/compute.googleapis.com', 'state': 'ENABLED'},
        ]),
        ('deployment_manager_deployment', PROJECT, rows,
         'collected' if rows else 'empty'),
        ('network', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                               PROJECT + '/global/networks/default'}]),
        ('subnetwork', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/regions/us-central1/subnetworks/default',
                                  'network': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/global/networks/default',
                                  'purpose': 'PRIVATE', 'state': 'READY'}]),
        ('image', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                             PROJECT + '/global/images/ready-image', 'status': 'READY'}]),
    ]
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_exact_policy_selfgrant_reaches_deputy():
    assert case() == {'serviceAccount:' + AGENT: 'conditional'}


def test_missing_policy_right_or_etag_is_not_positive():
    for options in ({'policy_read': False}, {'policy_write': False},
                    {'etag': False}, {'deployment': False},
                    {'split_deployment': True}):
        assert case(**options).get('serviceAccount:' + AGENT) != 'conditional'


def test_role_deny_and_runtime_guards():
    for options in ({'agent': False}, {'admin_role': False},
                    {'denied_update': True}, {'dm_api': False},
                    {'existing_update': True}):
        assert case(**options).get('serviceAccount:' + AGENT) != 'conditional'
