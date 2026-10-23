"""A created Dataproc session needs an accessible interactive runtime."""

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
             if e['id'] == 'gcp-dataproc-sessions-create-actas')


def case(*, create=True, get=True, actas=True, worker=True, node3=False,
         rm_api=True, api=True, agent=True, subnet=True, external=False,
         deny_create=False):
    bind = lambda role, member: {'role': role, 'members': [member]}
    runner = 'runner@p2.iam.gserviceaccount.com' if external else RUNNER
    run_project = 'projects/p2' if external else PROJECT
    caller_role = PROJECT + '/roles/sessionCaller'
    actas_role = PROJECT + '/roles/actas'
    worker_role = PROJECT + '/roles/worker'
    grants = ([bind(caller_role, SOURCE)] if create or get else []) + (
        [bind(worker_role, 'serviceAccount:' + runner)] if worker and not external else []) + (
        [bind('roles/dataproc.serviceAgent', AGENT)] if agent else []) + (
        [bind('roles/dataproc.serverlessNode', 'serviceAccount:' + runner),
         bind('roles/dataprocrm.nodeServiceAgent', 'serviceAccount:' + runner),
         bind('roles/dataprocrm.nodeServiceAgent', NODE_AGENT)]
        if node3 and not external else [])
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings': grants}]),
        ('iam_role', PROJECT, [
            {'name': caller_role, 'includedPermissions':
             (['dataproc.sessions.create'] if create else []) +
             (['dataproc.sessions.get'] if get else [])},
            {'name': actas_role, 'includedPermissions': ['iam.serviceAccounts.actAs']},
            {'name': worker_role, 'includedPermissions':
             ['dataproc.agents.create', 'dataproc.agents.get',
              'dataproc.agents.update', 'dataproc.agents.delete',
              'dataproc.tasks.lease', 'dataproc.tasks.reportStatus',
              'storage.objects.create', 'storage.objects.get',
              'storage.objects.delete', 'storage.objects.list']},
        ]),
        ('iam_deny_policy', PROJECT, [{'name': PROJECT + '/denyPolicies/no-sessions',
                                      'rules': [{'denyRule': {
                                          'deniedPermissions': ['dataproc.googleapis.com/sessions.create'],
                                          'deniedPrincipals': [SOURCE]}}]}]
         if deny_create else [], 'collected' if deny_create else 'empty'),
        ('service_usage', PROJECT, [
            {'name': PROJECT + '/services/dataproc.googleapis.com',
             'state': 'ENABLED' if api else 'DISABLED'},
            {'name': PROJECT + '/services/dataprocrm.googleapis.com',
             'state': 'ENABLED' if rm_api else 'DISABLED'}]),
        ('network', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                               PROJECT + '/global/networks/default'}]),
        ('subnetwork', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/regions/us-central1/subnetworks/default',
                                  'network': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/global/networks/default'}] if subnet else [],
         'collected' if subnet else 'empty'),
    ]
    if external:
        collections.extend([
            ('project', run_project, [{'projectId': 'p2', 'name': 'projects/456'}]),
            ('iam_policy', run_project, [{'name': run_project, 'bindings':
                                         [bind(worker_role, 'serviceAccount:' + runner)]
                                         if worker else []}]),
            ('iam_deny_policy', run_project, [], 'empty'),
        ])
    collections.append(('service_account', run_project, [
        {'email': runner, 'projectId': run_project.split('/')[1],
         'iamPolicy': {'bindings': [bind(actas_role, SOURCE)] if actas else []}}
    ]))
    snap = snapshot('gcp', collections)
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_old_and_new_interactive_runtimes():
    assert case() == [('serviceAccount:' + RUNNER, 'conditional')]
    assert case(worker=False, node3=True) == [('serviceAccount:' + RUNNER, 'conditional')]
    assert case(worker=False, node3=True, rm_api=False)[0][1] == 'unknown'


def test_absent_permissions_or_api_do_not_become_positive():
    assert case(create=False) == []
    assert case(actas=False) == []
    assert case(api=False) == []
    assert case(deny_create=True) == []
    assert case(get=False)[0][1] == 'unknown'
    assert case(worker=False)[0][1] == 'unknown'
    assert case(agent=False)[0][1] == 'unknown'
    assert case(subnet=False)[0][1] == 'unknown'


def test_cross_project_attachment_remains_unresolved():
    assert case(external=True)[0][1] == 'unknown'
