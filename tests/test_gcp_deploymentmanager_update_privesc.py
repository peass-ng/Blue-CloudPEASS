"""Direct updates need one exact deployment and an actionable deputy path."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
AGENT = '123@cloudservices.gserviceaccount.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-deploymentmanager-deployments-update')


def case(*, get=True, update=True, fingerprint=True, deployment=True,
         dm_api=True, agent=True, image=True, split=False):
    bind = lambda role, member: {'role': role, 'members': [member]}
    deputy_perms = ['compute.instances.create', 'compute.instances.setServiceAccount',
                    'compute.instances.setMetadata', 'compute.disks.create',
                    'compute.images.useReadOnly', 'compute.subnetworks.use',
                    'compute.subnetworks.useExternalIp', 'iam.serviceAccounts.actAs']
    rows = []
    if deployment:
        rows = [{'name': 'prior', **({'fingerprint': 'current'} if fingerprint else {})}]
        if split:
            rows.append({'name': 'other', 'fingerprint': 'current2'})
            rows[0]['iamPolicy'] = {'bindings': [bind(PROJECT + '/roles/getter', SOURCE)]}
            rows[1]['iamPolicy'] = {'bindings': [bind(PROJECT + '/roles/updater', SOURCE)]}
    source_perms = ([] if split else
                    (['deploymentmanager.deployments.get'] if get else []) +
                    (['deploymentmanager.deployments.update'] if update else []))
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings':
                                 ([bind(PROJECT + '/roles/source', SOURCE)] if source_perms else []) +
                                 ([bind(PROJECT + '/roles/deputy',
                                        'serviceAccount:' + AGENT)] if agent else [])}]),
        ('iam_role', PROJECT, [
            {'name': PROJECT + '/roles/source', 'includedPermissions': source_perms},
            {'name': PROJECT + '/roles/getter', 'includedPermissions':
             ['deploymentmanager.deployments.get'] if get else []},
            {'name': PROJECT + '/roles/updater', 'includedPermissions':
             ['deploymentmanager.deployments.update'] if update else []},
            {'name': PROJECT + '/roles/deputy', 'includedPermissions': deputy_perms},
        ]),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('service_account', PROJECT, [{'email': 'runner@p1.iam.gserviceaccount.com',
                                      'projectId': 'p1', 'iamPolicy': {'bindings': []}}]),
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
                             PROJECT + '/global/images/ready-image', 'status': 'READY'}]
         if image else [], 'collected' if image else 'empty'),
    ]
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_exact_deployment_update_reaches_agent():
    assert case() == {'serviceAccount:' + AGENT: 'conditional'}


def test_missing_update_or_disabled_api_has_no_path():
    assert case(update=False) == {}
    assert case(dm_api=False) == {}


def test_incomplete_deployment_or_deputy_path_is_not_positive():
    for options in ({'get': False}, {'fingerprint': False}, {'deployment': False},
                    {'agent': False}, {'image': False}, {'split': True}):
        assert case(**options).get('serviceAccount:' + AGENT) != 'conditional'
