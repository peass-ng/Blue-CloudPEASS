"""A Dataplex task reaches only a usable lake, payload, and execution identity."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
LAKE = PROJECT + '/locations/us-central1/lakes/main'
RUNNER = 'runner@p1.iam.gserviceaccount.com'
SOURCE = 'user:alice@example.com'
AGENT = 'serviceAccount:service-123@gcp-sa-dataplex.iam.gserviceaccount.com'
ENTRY = next(row for row in privesc.catalog()['entries']
             if row['id'] == 'gcp-dataplex-tasks-create-actas')


def case(*, lake=True, lake_state='ACTIVE', create=True, actas=True,
         dataplex=True, dataproc=True, worker=True, payload_write=True,
         payload_read=True, agent=True, deny_create=False, external=False,
         payload_bucket_external=False):
    runner = 'runner@p2.iam.gserviceaccount.com' if external else RUNNER
    run_project = 'projects/p2' if external else PROJECT
    binding = lambda role, member: {'role': role, 'members': [member]}
    creator = PROJECT + '/roles/taskCreator'
    actas_role = PROJECT + '/roles/actAs'
    worker_role = run_project + '/roles/worker'
    write_role = PROJECT + '/roles/payloadWriter'
    read_role = PROJECT + '/roles/payloadReader'
    project_bindings = ([binding(creator, SOURCE)] if create else []) + (
        [binding(worker_role, 'serviceAccount:' + runner)] if not external and worker else []) + (
        [binding('roles/dataplex.serviceAgent', AGENT)] if agent else [])
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings': project_bindings}]),
        ('iam_role', PROJECT, [
            {'name': creator, 'includedPermissions': ['dataplex.tasks.create']},
            {'name': actas_role, 'includedPermissions': ['iam.serviceAccounts.actAs']},
            {'name': write_role, 'includedPermissions': ['storage.objects.create']},
            {'name': read_role, 'includedPermissions': ['storage.objects.get']},
        ] + ([] if external else [{'name': worker_role, 'includedPermissions':
                                   ['dataproc.agents.create', 'dataproc.agents.get',
                                    'dataproc.agents.update', 'dataproc.agents.delete',
                                    'dataproc.tasks.lease', 'dataproc.tasks.reportStatus',
                                    'storage.objects.create', 'storage.objects.get',
                                    'storage.objects.delete', 'storage.objects.list']}])),
        ('iam_deny_policy', PROJECT, [
            {'name': PROJECT + '/denyPolicies/block-create', 'rules': [{'denyRule': {
                'deniedPermissions': ['dataplex.googleapis.com/tasks.create'],
                'deniedPrincipals': [SOURCE]}}]}
        ] if deny_create else [], 'collected' if deny_create else 'empty'),
        ('dataplex_privesc_lake', PROJECT, [
            {'name': LAKE, 'state': lake_state, 'iamPolicy': {'bindings': []}}
        ] if lake else [], 'collected' if lake else 'empty'),
        ('service_usage', PROJECT, [
            {'name': PROJECT + '/services/dataplex.googleapis.com',
             'state': 'ENABLED' if dataplex else 'DISABLED'},
            {'name': PROJECT + '/services/dataproc.googleapis.com',
             'state': 'ENABLED' if dataproc else 'DISABLED'},
        ]),
    ]
    bucket_scope = 'projects/p2' if payload_bucket_external else PROJECT
    collections.append(('bucket', bucket_scope, [{'name': 'payload-bucket',
                                                 '_coverage': {'iamPolicy': {'status': 'collected'}},
                                                 'iamPolicy': {'bindings': (
                                                     [binding(write_role, SOURCE)]
                                                     if payload_write else []) + (
                                                     [binding(read_role, 'serviceAccount:' + runner)]
                                                     if payload_read else [])}}]))
    if payload_bucket_external and not external:
        collections.extend([
            ('project', bucket_scope, [{'projectId': 'p2', 'name': 'projects/456'}]),
            ('iam_policy', bucket_scope, [{'name': bucket_scope, 'bindings': []}]),
            ('iam_deny_policy', bucket_scope, [], 'empty'),
            ('service_usage', bucket_scope, [], 'empty'),
            ('dataplex_privesc_lake', bucket_scope, [], 'empty'),
        ])
    if external:
        collections.extend([
            ('project', run_project, [{'projectId': 'p2', 'name': 'projects/456'}]),
            ('iam_policy', run_project, [{'name': run_project,
                                         'bindings': ([binding(worker_role,
                                                               'serviceAccount:' + runner)]
                                                      if worker else [])}]),
            ('iam_role', run_project, [{'name': worker_role, 'includedPermissions':
                                       ['dataproc.agents.create', 'dataproc.agents.get',
                                        'dataproc.agents.update', 'dataproc.agents.delete',
                                        'dataproc.tasks.lease', 'dataproc.tasks.reportStatus',
                                        'storage.objects.create', 'storage.objects.get',
                                        'storage.objects.delete', 'storage.objects.list']}]),
            ('iam_deny_policy', run_project, [], 'empty'),
            ('service_usage', run_project, [], 'empty'),
            ('dataplex_privesc_lake', run_project, [], 'empty'),
            ('bucket', run_project, [], 'empty'),
        ])
    collections.append(('service_account', run_project, [
        {'email': runner, 'projectId': run_project.split('/')[1],
         'iamPolicy': {'bindings': [binding(actas_role, SOURCE)] if actas else []}}
    ]))
    snap = snapshot('gcp', collections)
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_exact_lake_payload_and_worker_path():
    assert case() == [('serviceAccount:' + RUNNER, 'conditional')]


def test_absent_or_disabled_lake_service_and_permission_do_not_escalate():
    assert case(lake=False) == []
    assert case(lake_state='DELETING') == []
    assert case(create=False) == []
    assert case(actas=False) == []
    assert case(dataplex=False) == []
    assert case(dataproc=False) == []
    assert case(worker=False)[0][1] == 'unknown'
    assert case(deny_create=True) == []


def test_missing_payload_or_cross_project_prerequisite_stays_unresolved():
    assert case(payload_write=False)[0][1] == 'unknown'
    assert case(payload_bucket_external=True, payload_read=False)[0][1] == 'unknown'
    assert case(agent=False)[0][1] == 'unknown'
    assert case(external=True)[0][1] == 'unknown'
