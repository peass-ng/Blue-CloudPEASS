"""Init-action poisoning requires one live, replaceable object."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
VM = 'runner@p1.iam.gserviceaccount.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-dataproc-staging-object-replace')


def case(*, split=False, protected=False, metadata=True, absent=False, state='RUNNING',
         vm_read=True, scope=True, mapping=False, personal=False, api=True,
         delete=True):
    bind = lambda role, member: {'role': role, 'members': [member]}
    writer = PROJECT + '/roles/writer'
    deleter = PROJECT + '/roles/deleter'
    reader = PROJECT + '/roles/reader'
    uris = ['gs://first-bucket/init.sh'] + (['gs://second-bucket/init.sh'] if split else [])
    objects = {}
    for uri in uris:
        bucket = uri[5:].split('/', 1)[0]
        objects[uri] = {'status': 'not_found'} if absent else {'status': 'collected', 'metadata': {
            'generation': '123', 'temporaryHold': protected,
            'eventBasedHold': False, 'retentionExpirationTime': None,
            'retainUntilTime': None}} if metadata else {'status': 'unavailable'}
    config = {'initializationActions': [{'executableFile': uri} for uri in uris],
              'gceClusterConfig': {'serviceAccount': VM,
                                   'serviceAccountScopes': []},
              'softwareConfig': {'imageVersion': '2.2-debian12' if scope else '2.0-debian10',
                                 'properties': {'dataproc:dataproc.personal-auth.user':
                                                'alice@example.com'} if personal else {}}}
    if mapping:
        config['securityConfig'] = {'identityConfig': {
            'userServiceAccountMapping': {'alice@example.com':
                                          'mapped@p1.iam.gserviceaccount.com'}}}
    cluster = {'clusterName': 'main', 'projectId': 'p1', '_region': 'us-central1',
               'status': {'state': state}, 'config': config,
               '_initObjectMetadata': {'status': 'collected', 'objects': objects},
               '_coverage': {'iamPolicy': {'status': 'collected'}},
               'iamPolicy': {'bindings': []}}
    buckets = []
    for name in ('first-bucket', 'second-bucket') if split else ('first-bucket',):
        perms = ([bind(writer, SOURCE)] if name == 'first-bucket' else []) + (
            [bind(deleter, SOURCE)] if delete and (name == 'second-bucket' or not split) else []) + (
            [bind(reader, 'serviceAccount:' + VM)] if vm_read else [])
        buckets.append({'name': name, '_coverage': {'iamPolicy': {'status': 'collected'}},
                        'iamPolicy': {'bindings': perms}})
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings': []}]),
        ('iam_role', PROJECT, [
            {'name': writer, 'includedPermissions': ['storage.objects.create']},
            {'name': deleter, 'includedPermissions': ['storage.objects.delete']},
            {'name': reader, 'includedPermissions': ['storage.objects.get']},
        ]),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('service_account', PROJECT, [{'email': VM, 'projectId': 'p1',
                                      'iamPolicy': {'bindings': []}}]),
        ('dataproc_cluster', PROJECT, [cluster]),
        ('service_usage', PROJECT, [{'name': PROJECT + '/services/dataproc.googleapis.com',
                                    'state': 'ENABLED' if api else 'DISABLED'}]),
        ('bucket', PROJECT, buckets),
    ]
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_one_live_object_can_be_replaced_for_later_node():
    assert case() == {'serviceAccount:' + VM: 'conditional'}
    assert case(absent=True, delete=False) == {'serviceAccount:' + VM: 'conditional'}


def test_rights_on_different_objects_do_not_combine():
    assert case(split=True).get('serviceAccount:' + VM) != 'conditional'


def test_protected_or_unreadable_object_is_not_positive():
    assert case(protected=True).get('serviceAccount:' + VM) != 'conditional'
    assert case(delete=False).get('serviceAccount:' + VM) != 'conditional'
    assert case(vm_read=False).get('serviceAccount:' + VM) != 'conditional'
    assert case(metadata=False).get('serviceAccount:' + VM) != 'conditional'


def test_cluster_and_identity_conditions_are_respected():
    for options in ({'state': 'STOPPED'}, {'scope': False}, {'mapping': True},
                    {'personal': True}, {'api': False}):
        assert case(**options).get('serviceAccount:' + VM) != 'conditional'
