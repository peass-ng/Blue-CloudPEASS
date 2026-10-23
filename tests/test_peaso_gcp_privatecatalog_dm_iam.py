"""Shared Deployment Manager versions yield only bounded consumer IAM paths."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


ORG = 'organizations/123'
PROJECT = 'projects/p1'
CATALOG = 'catalogs/c1'
VERSION = CATALOG + '/products/p1/versions/v1'
SOURCE = 'user:operator@example.com'
AGENT = 'serviceAccount:456@cloudservices.gserviceaccount.com'
ROLE = ORG + '/roles/catalogEditor'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-privatecatalog-product-version-poison')


def report():
    return snapshot('gcp', [
        ('organization', ORG, [{'name': ORG}]),
        ('project', PROJECT, [{'name': 'projects/456', 'projectId': 'p1', 'parent': ORG}]),
        ('iam_role', ORG, [{'name': ROLE, 'includedPermissions':
                           ['cloudprivatecatalogproducer.products.update']}]),
        ('iam_policy', ORG, [{'name': ORG, 'bindings': []}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings': [
            {'role': 'roles/resourcemanager.projectIamAdmin', 'members': [AGENT]}]}]),
        ('service_account', PROJECT, [], 'empty'),
        ('service_catalog_version', ORG, [{
            'name': VERSION, 'product': CATALOG + '/products/p1', 'catalog': CATALOG,
            'catalogParent': '//cloudresourcemanager.googleapis.com/' + ORG,
            'catalogIamPolicy': {'bindings': [{'role': ROLE, 'members': [SOURCE]}]},
            'assetType': 'google.deploymentmanager.Template',
            'validatedAssetPresent': True,
            'consumerTargets': ['//cloudresourcemanager.googleapis.com/projects/456'],
        }]),
        ('iam_deny_policy', ORG, [], 'empty'),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('org_policy_effective', PROJECT, [], 'empty'),
    ])


def paths(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()
            if target.startswith('gcp_verified_authority:privatecatalog')]


def collection(snap, kind, scope=None):
    return next(row for row in snap['collections']
                if row['type'] == kind and (scope is None or row['scope'] == scope))


def test_exact_shared_version_and_stronger_consumer_agent_give_conditional_path():
    assert paths(report()) == [(
        'gcp_verified_authority:privatecatalog-dm-project-iam:' + VERSION + ':' + PROJECT,
        'conditional')]


def test_unshared_unvalidated_or_non_dm_versions_have_no_path():
    for change in ({'consumerTargets': []}, {'validatedAssetPresent': False},
                   {'assetType': 'google.cloudprivatecatalog.ListingOnly'},
                   {'catalogParent': '//cloudresourcemanager.googleapis.com/organizations/other'}):
        snap = report()
        collection(snap, 'service_catalog_version')['items'][0].update(change)
        assert not paths(snap)


def test_existing_source_iam_control_or_wrong_update_condition_has_no_path():
    snap = report()
    collection(snap, 'iam_policy', PROJECT)['items'][0]['bindings'].append(
        {'role': 'roles/resourcemanager.projectIamAdmin', 'members': [SOURCE]})
    assert not paths(snap)
    snap = report()
    collection(snap, 'service_catalog_version')['items'][0]['catalogIamPolicy']['bindings'][0]['condition'] = {
        'expression': "resource.name == 'catalogs/other/products/p1/versions/v1'"}
    assert not paths(snap)


def test_missing_agent_or_update_permission_cannot_be_positive():
    snap = report()
    collection(snap, 'iam_policy', PROJECT)['items'][0]['bindings'] = []
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))
    snap = report()
    collection(snap, 'service_catalog_version')['items'][0]['catalogIamPolicy']['bindings'] = []
    assert not paths(snap)


def test_folder_association_reaches_descendant_consumer_only():
    snap = report()
    collection(snap, 'project')['items'][0]['parent'] = 'folders/f1'
    snap['collections'].append({'type': 'folder', 'scope': 'folders/f1', 'service': 'folder',
                                'status': 'collected', 'items': [{'name': 'folders/f1', 'parent': ORG}],
                                'error': None})
    snap['collections'].append({'type': 'iam_deny_policy', 'scope': 'folders/f1',
                                'service': 'iam_deny_policy', 'status': 'empty', 'items': [], 'error': None})
    collection(snap, 'service_catalog_version')['items'][0]['consumerTargets'] = [
        '//cloudresourcemanager.googleapis.com/folders/f1']
    assert len(paths(snap)) == 1
    collection(snap, 'project')['items'][0]['parent'] = ORG
    assert not paths(snap)


def test_agent_deny_and_incomplete_catalog_policy_do_not_give_positive():
    snap = report()
    collection(snap, 'iam_deny_policy', PROJECT).update(
        status='collected', items=[{'name': PROJECT + '/denyPolicies/block-iam',
                                    'rules': [{'denyRule': {
                                        'deniedPermissions': ['resourcemanager.googleapis.com/projects.setIamPolicy'],
                                        'deniedPrincipals': [AGENT]}}]}])
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))
    snap = report()
    collection(snap, 'service_catalog_version')['status'] = 'denied'
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))
    snap = report()
    collection(snap, 'service_catalog_version')['items'][0]['catalogIamPolicy'] = {'bindings': {}}
    assert not paths(snap)


def test_conflicting_catalog_observations_do_not_create_a_path():
    snap = report()
    original = collection(snap, 'service_catalog_version')['items'][0]
    other = {**original, 'name': CATALOG + '/products/p1/versions/v2',
             'consumerTargets': []}
    collection(snap, 'service_catalog_version')['items'].append(other)
    assert not paths(snap)


def test_other_sensitive_agent_permission_remains_unresolved():
    snap = report()
    collection(snap, 'iam_policy', PROJECT)['items'][0]['bindings'][0]['role'] = 'roles/editor'
    assert not paths(snap)
    edges = [edge for edge in Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                                       admin_scopes={}).run() if edge.source.id == SOURCE]
    assert len(edges) == 1
    assert len(edges[0].targets) == 1
    target, grant = next(iter(edges[0].targets.items()))
    assert target.startswith('unresolved:gcp_verified_authority:') and grant.confidence == 'unknown'
