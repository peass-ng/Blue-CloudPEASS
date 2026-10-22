"""A Dataproc create edge needs the chosen identity and a usable workload."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
RUNNER = 'runner@p1.iam.gserviceaccount.com'
SOURCE = 'user:alice@example.com'
AGENT = 'serviceAccount:service-123@dataproc-accounts.iam.gserviceaccount.com'
NODE_AGENT = 'serviceAccount:service-123@gcp-sa-dataprocrmnode.iam.gserviceaccount.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-dataproc-clusters-batches-create-actas')


def case(*, batch=True, cluster=False, worker=True, script=True, api=True,
         subnet=True, agent=True, actas=True, external=False, denied=False,
         node3=False, rm_api=True):
    binding = lambda role, member: {'role': role, 'members': [member]}
    creator = PROJECT + '/roles/creator'
    worker_role = PROJECT + '/roles/worker'
    writer = PROJECT + '/roles/writer'
    reader = PROJECT + '/roles/reader'
    runner = ('runner@p2.iam.gserviceaccount.com' if external else RUNNER)
    target_project = ('projects/p2' if external else PROJECT)
    project_bindings = ([binding(creator, SOURCE)] if batch or cluster else []) + (
        [binding(worker_role, 'serviceAccount:' + runner)] if worker and not external else []) + (
        [binding('roles/dataproc.serviceAgent', AGENT)] if agent else []) + (
        [binding('roles/dataproc.serverlessNode', 'serviceAccount:' + runner),
         binding('roles/dataprocrm.nodeServiceAgent', 'serviceAccount:' + runner),
         binding('roles/dataprocrm.nodeServiceAgent', NODE_AGENT)]
        if node3 and not external else [])
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings': project_bindings}]),
        ('iam_role', PROJECT, [
            {'name': creator, 'includedPermissions':
             (['dataproc.batches.create'] if batch else []) +
             (['dataproc.clusters.create'] if cluster else [])},
            {'name': worker_role, 'includedPermissions':
             ['dataproc.agents.create', 'dataproc.agents.get',
              'dataproc.agents.update', 'dataproc.agents.delete',
              'dataproc.tasks.lease', 'dataproc.tasks.reportStatus',
              'storage.objects.create', 'storage.objects.get',
              'storage.objects.update', 'storage.objects.delete',
              'storage.objects.list']},
            {'name': writer, 'includedPermissions': ['storage.objects.create']},
            {'name': reader, 'includedPermissions': ['storage.objects.get']},
        ]),
        ('iam_deny_policy', PROJECT, [{'name': PROJECT + '/denyPolicies/no-batches',
                                      'rules': [{'denyRule': {'deniedPermissions':
                                                             ['dataproc.googleapis.com/batches.create'],
                                                             'deniedPrincipals': [SOURCE]}}]}]
         if denied else [], 'collected' if denied else 'empty'),
        ('service_usage', PROJECT, [{'name': PROJECT + '/services/dataproc.googleapis.com',
                                    'state': 'ENABLED' if api else 'DISABLED'},
                                   {'name': PROJECT + '/services/dataprocrm.googleapis.com',
                                    'state': 'ENABLED' if rm_api else 'DISABLED'}]),
        ('network', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                               PROJECT + '/global/networks/default'}]),
        ('subnetwork', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/regions/us-central1/subnetworks/default',
                                  'network': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/global/networks/default'}]
         if subnet else [], 'collected' if subnet else 'empty'),
        ('bucket', PROJECT, [{'name': 'payload-bucket',
                             '_coverage': {'iamPolicy': {'status': 'collected'}},
                             'iamPolicy': {'bindings': ([binding(writer, SOURCE)] if script else []) +
                                           [binding(reader, 'serviceAccount:' + runner)]}}]),
    ]
    if external:
        collections.extend([
            ('project', target_project, [{'projectId': 'p2', 'name': 'projects/456'}]),
            ('iam_policy', target_project, [{'name': target_project, 'bindings':
                                            [binding(worker_role, 'serviceAccount:' + runner)]
                                            if worker else []}]),
            ('iam_deny_policy', target_project, [], 'empty'),
        ])
    collections.append(('service_account', target_project, [
        {'email': runner, 'projectId': target_project.split('/')[1],
         'iamPolicy': {'bindings': [binding(PROJECT + '/roles/actas', SOURCE)] if actas else []}}
    ]))
    collections.append(('iam_role', target_project, [
        {'name': PROJECT + '/roles/actas', 'includedPermissions': ['iam.serviceAccounts.actAs']}
    ]))
    snap = snapshot('gcp', collections)
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_batch_and_cluster_paths_with_runnable_worker():
    assert case() == [('serviceAccount:' + RUNNER, 'conditional')]
    assert case(batch=False, cluster=True) == [('serviceAccount:' + RUNNER, 'conditional')]
    assert case(batch=False, cluster=True, script=False) == [
        ('serviceAccount:' + RUNNER, 'conditional')]
    assert case(worker=False, node3=True) == [('serviceAccount:' + RUNNER, 'conditional')]
    assert case(worker=False, node3=True, rm_api=False)[0][1] == 'unknown'


def test_absent_core_prerequisites_do_not_create_positive_edge():
    assert case(batch=False) == []
    assert case(actas=False) == []
    assert case(api=False) == []
    assert case(denied=True) == []
    assert case(worker=False)[0][1] == 'unknown'
    assert case(script=False)[0][1] == 'unknown'
    assert case(subnet=False)[0][1] == 'unknown'
    assert case(agent=False)[0][1] == 'unknown'


def test_cross_project_attachment_is_not_assumed():
    assert case(external=True)[0][1] == 'unknown'
