"""Cluster self-grants require one exact runnable cluster and a job code path."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
RUNNER = 'runner@p1.iam.gserviceaccount.com'
SOURCE = 'user:alice@example.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-dataproc-clusters-setiampolicy')


def case(*, policy_write=True, policy_read=True, job=True, state='RUNNING',
         script=True, api=True, use=False, region=True, denied=False,
         image='2.2-debian12', scopes=None):
    bind = lambda role, member: {'role': role, 'members': [member]}
    caller = PROJECT + '/roles/caller'
    writer = PROJECT + '/roles/scriptWriter'
    reader = PROJECT + '/roles/scriptReader'
    perms = (['dataproc.clusters.setIamPolicy'] if policy_write else []) + (
        ['dataproc.clusters.getIamPolicy'] if policy_read else []) + (
        ['dataproc.jobs.create'] if job else []) + (
        ['dataproc.clusters.use'] if use else [])
    cluster = {'clusterName': 'main', 'projectId': 'p1',
               'status': {'state': state},
               'config': {'gceClusterConfig': {'serviceAccount': RUNNER,
                                              'serviceAccountScopes': scopes or []},
                          'softwareConfig': {'imageVersion': image} if image else {}},
               '_coverage': {'iamPolicy': {'status': 'collected'}},
               'iamPolicy': {'bindings': []}}
    if region:
        cluster['_region'] = 'us-central1'
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings':
                                 [bind(caller, SOURCE)] if perms else []}]),
        ('iam_role', PROJECT, [
            {'name': caller, 'includedPermissions': perms},
            {'name': writer, 'includedPermissions': ['storage.objects.create']},
            {'name': reader, 'includedPermissions': ['storage.objects.get']},
        ]),
        ('iam_deny_policy', PROJECT, [{'name': PROJECT + '/denyPolicies/block-policy',
                                      'rules': [{'denyRule': {
                                          'deniedPermissions':
                                          ['dataproc.googleapis.com/clusters.setIamPolicy'],
                                          'deniedPrincipals': [SOURCE]}}]}]
         if denied else [], 'collected' if denied else 'empty'),
        ('service_account', PROJECT, [{'email': RUNNER, 'projectId': 'p1',
                                      'iamPolicy': {'bindings': []}}]),
        ('dataproc_cluster', PROJECT, [cluster]),
        ('service_usage', PROJECT, [{'name': PROJECT + '/services/dataproc.googleapis.com',
                                    'state': 'ENABLED' if api else 'DISABLED'}]),
        ('bucket', PROJECT, [{'name': 'payload-bucket',
                             '_coverage': {'iamPolicy': {'status': 'collected'}},
                             'iamPolicy': {'bindings':
                                           ([bind(writer, SOURCE)] if script else []) +
                                           [bind(reader, 'serviceAccount:' + RUNNER)]}}]),
    ]
    snap = snapshot('gcp', collections)
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_running_cluster_with_policy_and_readable_script():
    assert case() == [('serviceAccount:' + RUNNER, 'conditional')]


def test_denied_or_missing_permissions_do_not_become_positive():
    assert case(policy_write=False) == []
    assert case(job=False) == []
    assert case(denied=True) == []
    assert case(api=False) == []
    assert case(use=True) == []
    assert case(policy_read=False)[0][1] == 'unknown'
    assert case(script=False)[0][1] == 'unknown'
    assert case(state='STOPPED')[0][1] == 'unknown'
    assert case(image='2.0-debian10')[0][1] == 'unknown'
    assert case(image=None)[0][1] == 'unknown'
    assert case(image='2.0-debian10', scopes=[
        'https://www.googleapis.com/auth/cloud-platform']) == [
            ('serviceAccount:' + RUNNER, 'conditional')]
    assert case(region=False) == []
