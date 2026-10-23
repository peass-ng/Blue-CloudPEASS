"""A Deployment Manager edge needs an eligible customer and a runnable deputy VM."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
AGENT = '123@cloudservices.gserviceaccount.com'
RUNNER = 'runner@p1.iam.gserviceaccount.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-deploymentmanager-deployments-create')


def case(*, create=True, dm_api=True, compute_api=True, existing=True,
         agent=True, image=True, subnet=True, account=True, agent_actas=True,
         source_vm=False, editor=False, editor_role=True):
    bind = lambda role, member: {'role': role, 'members': [member]}
    creator = PROJECT + '/roles/creator'
    deputy = PROJECT + '/roles/deputy'
    agent_perms = ['compute.instances.create', 'compute.instances.setServiceAccount',
                   'compute.instances.setMetadata', 'compute.disks.create',
                   'compute.images.useReadOnly', 'compute.subnetworks.use',
                   'compute.subnetworks.useExternalIp'] + (
                       ['iam.serviceAccounts.actAs'] if agent_actas else [])
    source_perms = (['deploymentmanager.deployments.create'] if create else []) + (
        agent_perms if source_vm else [])
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings':
                                 ([bind(creator, SOURCE)] if source_perms else []) +
                                 ([bind('roles/editor' if editor else deputy,
                                        'serviceAccount:' + AGENT)] if agent else [])}]),
        ('iam_role', PROJECT, [
            {'name': creator, 'includedPermissions': source_perms},
            {'name': deputy, 'includedPermissions': agent_perms},
        ]),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('iam_role_builtin', PROJECT,
         [{'name': 'roles/editor', 'includedPermissions': agent_perms}]
         if editor and editor_role else [], 'collected' if editor and editor_role else 'empty'),
        ('service_account', PROJECT, ([{'email': RUNNER, 'projectId': 'p1',
                                      'iamPolicy': {'bindings': []}}] if account else [])),
        ('service_usage', PROJECT, [
            {'name': PROJECT + '/services/deploymentmanager.googleapis.com',
             'state': 'ENABLED' if dm_api else 'DISABLED'},
            {'name': PROJECT + '/services/compute.googleapis.com',
             'state': 'ENABLED' if compute_api else 'DISABLED'},
        ]),
        ('deployment_manager_deployment', PROJECT,
         [{'name': 'prior-deployment', 'fingerprint': 'abc'}] if existing else [],
         'collected' if existing else 'empty'),
        ('network', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                               PROJECT + '/global/networks/default'}]),
        ('subnetwork', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/regions/us-central1/subnetworks/default',
                                  'network': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/global/networks/default',
                                  'purpose': 'PRIVATE', 'state': 'READY'}]
         if subnet else [], 'collected' if subnet else 'empty'),
        ('image', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                             PROJECT + '/global/images/ready-image', 'status': 'READY'}]
         if image else [], 'collected' if image else 'empty'),
    ]
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_existing_customer_with_verified_agent_vm_path():
    assert case() == {'serviceAccount:' + AGENT: 'conditional'}
    assert case(editor=True) == {'serviceAccount:' + AGENT: 'conditional'}
    assert case(editor=True, editor_role=False).get('serviceAccount:' + AGENT) != 'conditional'


def test_create_permission_and_live_apis_are_required():
    assert case(create=False) == {}
    assert case(dm_api=False) == {}
    assert case(compute_api=False).get('serviceAccount:' + AGENT) != 'conditional'


def test_unknown_customer_or_missing_vm_prerequisites_are_not_positive():
    for options in ({'existing': False}, {'agent': False}, {'image': False},
                    {'subnet': False}, {'account': False}, {'agent_actas': False},
                    {'source_vm': True}):
        assert case(**options).get('serviceAccount:' + AGENT) != 'conditional'
