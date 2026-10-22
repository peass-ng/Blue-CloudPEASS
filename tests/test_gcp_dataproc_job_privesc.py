"""Existing-cluster job submission needs project access and runnable code."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
VM = 'runner@p1.iam.gserviceaccount.com'
MAPPED = 'mapped@p1.iam.gserviceaccount.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-dataproc-jobs-create-existing-cluster')


def case(*, jobs=True, use=True, script=True, readable=True, state='RUNNING',
         api=True, region=True, image='2.2-debian12', scopes=(), mapped=False,
         mapped_user='alice@example.com', token=True, personal=False,
         use_only_on_cluster=False, jobs_only_on_cluster=False):
    caller = PROJECT + '/roles/caller'
    cluster_role = PROJECT + '/roles/clusterUser'
    writer = PROJECT + '/roles/writer'
    reader = PROJECT + '/roles/reader'
    project_perms = (['dataproc.jobs.create'] if jobs and not jobs_only_on_cluster else []) + (
        [] if use_only_on_cluster else ['dataproc.clusters.use'] if use else [])
    cluster_perms = (['dataproc.clusters.use'] if use and use_only_on_cluster else []) + (
        ['dataproc.jobs.create'] if jobs and jobs_only_on_cluster else [])
    bind = lambda role, member: {'role': role, 'members': [member]}
    config = {'gceClusterConfig': {'serviceAccount': VM,
                                  'serviceAccountScopes': list(scopes)},
              'softwareConfig': {'imageVersion': image,
                                 'properties': {'dataproc:dataproc.personal-auth.user':
                                                'alice@example.com'} if personal else {}}}
    if mapped:
        config['securityConfig'] = {'identityConfig': {
            'userServiceAccountMapping': {mapped_user: MAPPED}}}
    cluster = {'clusterName': 'main', 'projectId': 'p1', 'status': {'state': state},
               'config': config, '_coverage': {'iamPolicy': {'status': 'collected'}},
               'iamPolicy': {'bindings': [bind(cluster_role, SOURCE)] if cluster_perms else []}}
    if region:
        cluster['_region'] = 'us-central1'
    target_email = MAPPED if mapped else VM
    target_policy = {'bindings': [bind('roles/iam.serviceAccountTokenCreator',
                                        'serviceAccount:' + VM)]} if token else {'bindings': []}
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings':
                                 [bind(caller, SOURCE)] if project_perms else []}]),
        ('iam_role', PROJECT, [
            {'name': caller, 'includedPermissions': project_perms},
            {'name': cluster_role, 'includedPermissions': cluster_perms},
            {'name': writer, 'includedPermissions': ['storage.objects.create']},
            {'name': reader, 'includedPermissions': ['storage.objects.get']},
        ]),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('service_account', PROJECT, [
            {'email': VM, 'projectId': 'p1', 'iamPolicy': {'bindings': []}},
            {'email': MAPPED, 'projectId': 'p1', 'iamPolicy': target_policy},
        ]),
        ('dataproc_cluster', PROJECT, [cluster]),
        ('service_usage', PROJECT, [{'name': PROJECT + '/services/dataproc.googleapis.com',
                                    'state': 'ENABLED' if api else 'DISABLED'}]),
        ('bucket', PROJECT, [{'name': 'payload-bucket',
                             '_coverage': {'iamPolicy': {'status': 'collected'}},
                             'iamPolicy': {'bindings':
                                           ([bind(writer, SOURCE)] if script else []) +
                                           ([bind(reader, 'serviceAccount:' + target_email)]
                                            if readable else [])}}]),
    ]
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_project_job_grant_and_cluster_use_with_payload():
    assert case() == {'serviceAccount:' + VM: 'conditional'}
    assert case(use_only_on_cluster=True).get('serviceAccount:' + VM) == 'conditional'


def test_missing_grants_and_disabled_api_do_not_produce_positive():
    assert case(jobs=False) == {}
    assert case(jobs_only_on_cluster=True).get('serviceAccount:' + VM) != 'conditional'
    assert case(use=False) == {}
    assert case(api=False) == {}


def test_unresolved_payload_identity_or_cluster_is_not_positive():
    for options in ({'script': False}, {'readable': False}, {'state': 'STOPPED'},
                    {'region': False}, {'image': '2.0-debian10'}, {'personal': True}):
        assert case(**options).get('serviceAccount:' + VM) != 'conditional'


def test_multi_tenant_job_targets_mapped_account_only():
    result = case(mapped=True, scopes=['https://www.googleapis.com/auth/iam'])
    assert result.get('serviceAccount:' + MAPPED) == 'conditional'
    assert result.get('serviceAccount:' + VM) != 'conditional'
    assert case(mapped=True, token=False, scopes=[
        'https://www.googleapis.com/auth/iam']).get('serviceAccount:' + MAPPED) != 'conditional'
    assert case(mapped=True, mapped_user='bob@example.com', scopes=[
        'https://www.googleapis.com/auth/iam']).get('serviceAccount:' + MAPPED) != 'conditional'
