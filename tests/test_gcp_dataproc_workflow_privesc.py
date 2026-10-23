"""A managed workflow needs a runnable cluster and script, not only IAM verbs."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
RUNNER = 'runner@p1.iam.gserviceaccount.com'
AGENT = 'serviceAccount:service-123@dataproc-accounts.iam.gserviceaccount.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-dataproc-workflowtemplates-actas')


def case(*, create=True, instantiate=True, actas=True, worker=True,
         script=True, api=True, subnet=True, agent=True, external=False,
         inline=False, policy=False):
    bind = lambda role, member: {'role': role, 'members': [member]}
    creator = PROJECT + '/roles/workflowCreator'
    worker_role = PROJECT + '/roles/worker'
    writer = PROJECT + '/roles/writer'
    reader = PROJECT + '/roles/reader'
    actas_role = PROJECT + '/roles/actas'
    runner = 'runner@p2.iam.gserviceaccount.com' if external else RUNNER
    target_project = 'projects/p2' if external else PROJECT
    project_bindings = ([bind(creator, SOURCE)] if create or instantiate or inline or policy else []) + (
        [bind(worker_role, 'serviceAccount:' + runner)] if worker and not external else []) + (
        [bind('roles/dataproc.serviceAgent', AGENT)] if agent else [])
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings': project_bindings}]),
        ('iam_role', PROJECT, [
            {'name': creator, 'includedPermissions':
             (['dataproc.workflowTemplates.create'] if create else []) +
             (['dataproc.workflowTemplates.instantiate'] if instantiate else []) +
             (['dataproc.workflowTemplates.instantiateInline'] if inline else []) +
             (['dataproc.workflowTemplates.setIamPolicy'] if policy else [])},
            {'name': worker_role, 'includedPermissions':
             ['dataproc.agents.create', 'dataproc.agents.get',
              'dataproc.agents.update', 'dataproc.agents.delete',
              'dataproc.tasks.lease', 'dataproc.tasks.reportStatus',
              'storage.objects.create', 'storage.objects.get',
              'storage.objects.delete', 'storage.objects.list']},
            {'name': writer, 'includedPermissions': ['storage.objects.create']},
            {'name': reader, 'includedPermissions': ['storage.objects.get']},
            {'name': actas_role, 'includedPermissions': ['iam.serviceAccounts.actAs']},
        ]),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('service_usage', PROJECT, [{'name': PROJECT + '/services/dataproc.googleapis.com',
                                    'state': 'ENABLED' if api else 'DISABLED'}]),
        ('network', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                               PROJECT + '/global/networks/default'}]),
        ('subnetwork', PROJECT, [{'selfLink': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/regions/us-central1/subnetworks/default',
                                  'network': 'https://www.googleapis.com/compute/v1/' +
                                  PROJECT + '/global/networks/default'}]
         if subnet else [], 'collected' if subnet else 'empty'),
        ('bucket', PROJECT, [{'name': 'payload-bucket',
                             '_coverage': {'iamPolicy': {'status': 'collected'}},
                             'iamPolicy': {'bindings':
                                           ([bind(writer, SOURCE)] if script else []) +
                                           [bind(reader, 'serviceAccount:' + runner)]}}]),
    ]
    if external:
        collections += [
            ('project', target_project, [{'projectId': 'p2', 'name': 'projects/456'}]),
            ('iam_policy', target_project, [{'name': target_project, 'bindings':
                                            [bind(worker_role, 'serviceAccount:' + runner)]
                                            if worker else []}]),
            ('iam_deny_policy', target_project, [], 'empty'),
        ]
    collections.append(('service_account', target_project, [
        {'email': runner, 'projectId': target_project.split('/')[1],
         'iamPolicy': {'bindings': [bind(actas_role, SOURCE)] if actas else []}}
    ]))
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_complete_managed_workflow_can_use_chosen_account():
    assert case() == {'serviceAccount:' + RUNNER: 'conditional'}
    assert case(create=False, instantiate=False, inline=True) == {
        'serviceAccount:' + RUNNER: 'conditional'}


def test_missing_create_instantiate_or_actas_has_no_positive():
    assert case(create=False).get('serviceAccount:' + RUNNER) != 'conditional'
    assert case(instantiate=False).get('serviceAccount:' + RUNNER) != 'conditional'
    assert case(actas=False).get('serviceAccount:' + RUNNER) != 'conditional'
    assert case(instantiate=False, policy=True).get('serviceAccount:' + RUNNER) != 'conditional'


def test_runtime_and_payload_are_not_assumed():
    for options in ({'worker': False}, {'script': False}, {'api': False},
                    {'subnet': False}, {'agent': False}):
        assert case(**options).get('serviceAccount:' + RUNNER) != 'conditional'
    assert all(value != 'conditional' for value in case(external=True).values())
