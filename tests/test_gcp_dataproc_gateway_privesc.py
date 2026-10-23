"""Notebook gateway pivots resolve the identity and exact cluster access."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
VM = 'runner@p1.iam.gserviceaccount.com'
MAPPED = 'mapped@p1.iam.gserviceaccount.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-dataproc-component-gateway-existing-cluster')


def case(*, permissions=('dataproc.clusters.get', 'dataproc.clusters.use'),
         gateway=True, component='JUPYTER', url=True, state='RUNNING',
         api=True, image='2.2-debian12', scopes=(), mapped=False,
         token=True, personal=False, other_user=False):
    role = PROJECT + '/roles/caller'
    bindings = [{'role': role, 'members': [SOURCE]}] if permissions else []
    endpoint = {'enableHttpPortAccess': gateway, 'httpPorts': {
        'Jupyter': ('https://main-m.dataproc.googleusercontent.com/jupyter/'
                    if url else '')}}
    config = {
        'endpointConfig': endpoint,
        'softwareConfig': {'imageVersion': image,
                           'optionalComponents': [component],
                           'properties': {'dataproc:dataproc.personal-auth.user':
                                          'alice@example.com'} if personal else {}},
        'gceClusterConfig': {'serviceAccount': VM, 'serviceAccountScopes': list(scopes)},
    }
    if mapped:
        config['securityConfig'] = {'identityConfig': {
            'userServiceAccountMapping': {
                'bob@example.com' if other_user else 'alice@example.com': MAPPED}}}
    cluster = {'clusterName': 'main', 'projectId': 'p1', '_region': 'us-central1',
               'status': {'state': state}, 'config': config,
               '_coverage': {'iamPolicy': {'status': 'collected'}},
               'iamPolicy': {'bindings': []}}
    target_policy = {'bindings': [{'role': 'roles/iam.serviceAccountTokenCreator',
                                   'members': ['serviceAccount:' + VM]}]} if token else {'bindings': []}
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings': bindings}]),
        ('iam_role', PROJECT, [{'name': role, 'includedPermissions': list(permissions)}]),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('service_account', PROJECT, [
            {'email': VM, 'projectId': 'p1', 'iamPolicy': {'bindings': []}},
            {'email': MAPPED, 'projectId': 'p1', 'iamPolicy': target_policy},
        ]),
        ('dataproc_cluster', PROJECT, [cluster]),
        ('service_usage', PROJECT, [{'name': PROJECT + '/services/dataproc.googleapis.com',
                                    'state': 'ENABLED' if api else 'DISABLED'}]),
    ]
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_standard_gateway_uses_vm_identity():
    assert case() == {'serviceAccount:' + VM: 'conditional'}


def test_missing_access_or_disabled_api_has_no_positive():
    assert case(permissions=('dataproc.clusters.get',)) == {}
    assert case(permissions=()) == {}
    assert case(api=False) == {}


def test_unconfirmed_gateway_or_runtime_remains_unknown():
    for options in ({'gateway': False}, {'component': 'HIVE_WEBHCAT'},
                    {'url': False}, {'state': 'STOPPED'}, {'personal': True},
                    {'image': '2.0-debian10'}):
        assert case(**options).get('serviceAccount:' + VM) != 'conditional'


def test_multi_tenant_gateway_uses_only_mapped_account():
    result = case(mapped=True, scopes=['https://www.googleapis.com/auth/iam'])
    assert result.get('serviceAccount:' + MAPPED) == 'conditional'
    assert result.get('serviceAccount:' + VM) != 'conditional'
    assert case(mapped=True, token=False, scopes=[
        'https://www.googleapis.com/auth/iam']).get('serviceAccount:' + MAPPED) != 'conditional'
    assert case(mapped=True, other_user=True, scopes=[
        'https://www.googleapis.com/auth/iam']).get('serviceAccount:' + MAPPED) != 'conditional'
