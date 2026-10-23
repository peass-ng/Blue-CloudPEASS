"""Dataform actAs needs an execution route and a new exact BigQuery table read."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
OTHER = 'projects/p2'
LOCATION = PROJECT + '/locations/us-central1'
DEST = PROJECT + '/datasets/output'
SOURCE_DATASET = OTHER + '/datasets/private'
TABLE = SOURCE_DATASET + '/tables/records'
EMAIL = 'runner@p1.iam.gserviceaccount.com'
SA = 'serviceAccount:' + EMAIL
AGENT = 'serviceAccount:service-111@gcp-sa-dataform.iam.gserviceaccount.com'
CALLER = 'user:operator@example.com'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-dataform-workflow-invocation-actas')


def report():
    caller_role = PROJECT + '/roles/dataformCaller'
    runner_role = PROJECT + '/roles/runner'
    reader_role = OTHER + '/roles/privateReader'
    return snapshot('gcp', [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/111'}]),
        ('project', OTHER, [{'projectId': 'p2', 'name': 'projects/222'}]),
        ('iam_role', PROJECT, [
            {'name': caller_role, 'includedPermissions': [
                'iam.serviceAccounts.actAs', 'dataform.repositories.create',
                'bigquery.tables.getData', 'bigquery.datasets.get',
                'bigquery.tables.create', 'bigquery.tables.updateData']},
            {'name': runner_role, 'includedPermissions': [
                'bigquery.jobs.create', 'bigquery.datasets.get', 'bigquery.tables.create',
                'bigquery.tables.updateData']}]),
        ('iam_role', OTHER, [{'name': reader_role, 'includedPermissions':
                             ['bigquery.tables.getData']}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings': [
            {'role': caller_role, 'members': [CALLER]},
            {'role': runner_role, 'members': [SA]}]}]),
        ('iam_policy', OTHER, [{'name': OTHER, 'bindings': [
            {'role': reader_role, 'members': [SA]}]}]),
        ('service_account', PROJECT, [{'email': EMAIL, 'projectId': 'p1',
            'iamPolicy': {'bindings': [
                {'role': 'roles/iam.serviceAccountTokenCreator', 'members': [AGENT]},
                {'role': 'roles/iam.serviceAccountUser', 'members': [AGENT]}]}}]),
        ('dataform_privesc_location', PROJECT, [{'name': LOCATION,
            'creatorRoleConfig': {}, 'repositories': []}]),
        ('bigquery_dataset', PROJECT, [{'name': DEST, 'location': 'US', 'access': [],
            '_coverage': {'datasetDetails': {'status': 'collected'}}}]),
        ('bigquery_dataset', OTHER, [{'name': SOURCE_DATASET, 'location': 'US', 'access': [],
            '_coverage': {'datasetDetails': {'status': 'collected'}}}]),
        ('bigquery_table', OTHER, [{'name': TABLE, 'type': 'TABLE',
            'schema': {'fields': [{'name': 'value'}]}, '_schema_full': True,
            'iamPolicy': {'bindings': []},
            '_coverage': {'iamPolicy': {'status': 'collected'},
                          'tableDetails': {'status': 'collected'}}}]),
        ('bigquery_row_policy_inventory', OTHER, [{
            'name': TABLE + '/rowAccessPolicyInventory', 'table': TABLE,
            'status': 'collected', 'policies': []}]),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('iam_deny_policy', OTHER, [], 'empty'),
    ])


def paths(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == CALLER
            for target, grant in edge.targets.items()]


def collection(snap, kind, scope=PROJECT):
    return next(c for c in snap['collections'] if c['type'] == kind and c['scope'] == scope)


def test_create_route_and_exact_table_read_gain_is_conditional():
    assert paths(report()) == [(
        'gcp_verified_authority:dataform_workflow:' + SA, 'conditional')]


def test_creator_grant_disabled_or_agent_token_missing_cannot_be_positive():
    snap = report()
    collection(snap, 'dataform_privesc_location')['items'][0]['creatorRoleConfig'] = {
        'disableGrant': True}
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))
    snap = report()
    collection(snap, 'service_account')['items'][0]['iamPolicy']['bindings'] = []
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_manual_invocation_needs_agent_token_but_not_agent_actas():
    snap = report()
    bindings = collection(snap, 'service_account')['items'][0]['iamPolicy']['bindings']
    bindings[:] = [binding for binding in bindings
                   if binding['role'] != 'roles/iam.serviceAccountUser']
    assert paths(snap) == [(
        'gcp_verified_authority:dataform_workflow:' + SA, 'conditional')]


def test_source_already_reads_table_or_location_mismatch_has_no_positive():
    snap = report()
    collection(snap, 'iam_policy', OTHER)['items'][0]['bindings'][0]['members'].append(CALLER)
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))
    snap = report()
    collection(snap, 'bigquery_dataset', OTHER)['items'][0]['location'] = 'EU'
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_result_table_requires_data_write_permission():
    snap = report()
    collection(snap, 'iam_role')['items'][1]['includedPermissions'].remove(
        'bigquery.tables.updateData')
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_protected_dataset_write_gain_needs_both_write_rights_and_exact_policy():
    snap = report()
    role = collection(snap, 'iam_role', OTHER)['items'][0]
    role['includedPermissions'] = [
        'bigquery.datasets.get', 'bigquery.tables.create',
        'bigquery.tables.updateData']
    assert paths(snap) == [(
        'gcp_verified_authority:dataform_workflow:' + SA, 'conditional')]

    role['includedPermissions'].remove('bigquery.tables.updateData')
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))

    role['includedPermissions'].append('bigquery.tables.updateData')
    collection(snap, 'iam_policy', OTHER)['items'][0]['bindings'][0]['members'].append(CALLER)
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))

    collection(snap, 'iam_policy', OTHER)['items'][0]['bindings'][0]['members'].remove(CALLER)
    collection(snap, 'bigquery_dataset', OTHER)['items'][0]['datasetType'] = 'LINKED'
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))

    collection(snap, 'bigquery_dataset', OTHER)['items'][0]['datasetType'] = 'DEFAULT'
    collection(snap, 'bigquery_dataset', OTHER)['status'] = 'denied'
    collection(snap, 'bigquery_dataset', OTHER)['items'] = []
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_protected_table_export_needs_exact_caller_readable_bucket():
    snap = report()
    runner = collection(snap, 'iam_role')['items'][1]
    runner['includedPermissions'].remove('bigquery.tables.create')
    runner['includedPermissions'].remove('bigquery.tables.updateData')
    source_reader = collection(snap, 'iam_role', OTHER)['items'][0]
    source_reader['includedPermissions'].append('bigquery.tables.export')
    storage_role = PROJECT + '/roles/exportBucket'
    collection(snap, 'iam_role')['items'].append({
        'name': storage_role, 'includedPermissions': [
            'storage.objects.create', 'storage.objects.delete']})
    collection(snap, 'iam_role')['items'].append({
        'name': PROJECT + '/roles/exportReader',
        'includedPermissions': ['storage.objects.get']})
    snap['collections'].append({'type': 'bucket', 'scope': PROJECT,
                                'status': 'collected', 'items': [{
                                    'name': 'export-output', 'location': 'US',
                                    '_representation': 'full',
                                    'iamConfiguration': {'uniformBucketLevelAccess': {
                                        'enabled': True}},
                                    'iamPolicy': {'bindings': [
                                        {'role': storage_role, 'members': [SA]},
                                        {'role': PROJECT + '/roles/exportReader',
                                         'members': [CALLER]}]},
                                    '_coverage': {'iamPolicy': {'status': 'collected'}}}]})
    assert paths(snap) == [(
        'gcp_verified_authority:dataform_workflow:' + SA, 'conditional')]
    collection(snap, 'bucket')['items'][0]['location'] = 'EU'
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))
    collection(snap, 'bucket')['items'][0]['location'] = 'US'
    collection(snap, 'bucket')['items'][0]['iamConfiguration'][
        'uniformBucketLevelAccess']['enabled'] = False
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_existing_repository_grant_works_without_project_create():
    snap = report()
    collection(snap, 'iam_role')['items'][0]['includedPermissions'].remove(
        'dataform.repositories.create')
    repo = LOCATION + '/repositories/existing'
    collection(snap, 'dataform_privesc_location')['items'][0]['repositories'] = [{
        'name': repo, 'serviceAccount': EMAIL,
        'iamPolicy': {'bindings': [
            {'role': 'roles/dataform.admin', 'members': [CALLER]}]}}]
    assert paths(snap) == [(
        'gcp_verified_authority:dataform_workflow:' + SA, 'conditional')]
    collection(snap, 'dataform_privesc_location')['items'][0]['repositories'][0][
        'iamPolicy']['bindings'][0]['condition'] = {
            'expression': "resource.name == 'projects/p1/locations/us-central1/repositories/other'"}
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_existing_repository_direct_commit_route_is_sufficient():
    snap = report()
    collection(snap, 'iam_role')['items'][0]['includedPermissions'].remove(
        'dataform.repositories.create')
    role = PROJECT + '/roles/dataformCommitter'
    collection(snap, 'iam_role')['items'].append({
        'name': role, 'includedPermissions': [
            'dataform.repositories.commit', 'dataform.compilationResults.create',
            'dataform.workflowInvocations.create']})
    repo = LOCATION + '/repositories/existing'
    collection(snap, 'dataform_privesc_location')['items'][0]['repositories'] = [{
        'name': repo, 'serviceAccount': EMAIL,
        'iamPolicy': {'bindings': [{'role': role, 'members': [CALLER]}]}}]
    assert paths(snap) == [(
        'gcp_verified_authority:dataform_workflow:' + SA, 'conditional')]
    collection(snap, 'iam_role')['items'][-1]['includedPermissions'].remove(
        'dataform.compilationResults.create')
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_private_workspace_config_does_not_assume_creator_route():
    snap = report()
    collection(snap, 'dataform_privesc_location')['items'][0]['enablePrivateWorkspace'] = True
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_agent_token_deny_and_incomplete_dataform_inventory_do_not_give_positive():
    snap = report()
    collection(snap, 'iam_deny_policy', PROJECT).update(
        status='collected', items=[{'name': PROJECT + '/denyPolicies/block-token',
                                    'rules': [{'denyRule': {
                                        'deniedPermissions': [
                                            'iam.googleapis.com/serviceAccounts.getAccessToken'],
                                        'deniedPrincipals': [AGENT]}}]}])
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))
    snap = report()
    collection(snap, 'dataform_privesc_location')['status'] = 'denied'
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_existing_repository_policy_write_can_self_grant_only_with_complete_policy_evidence():
    snap = report()
    role = collection(snap, 'iam_role')['items'][0]
    role['includedPermissions'].remove('dataform.repositories.create')
    role['includedPermissions'].append('dataform.repositories.setIamPolicy')
    repo = LOCATION + '/repositories/existing'
    collection(snap, 'dataform_privesc_location')['items'][0]['repositories'] = [{
        'name': repo, 'serviceAccount': EMAIL, 'iamPolicy': {'bindings': []}}]
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))

    snap['collections'].append({'type': 'org_policy_effective', 'scope': PROJECT,
                                'status': 'empty', 'items': []})
    assert paths(snap) == [(
        'gcp_verified_authority:dataform_workflow:' + SA, 'conditional')]

    collection(snap, 'org_policy_effective')['status'] = 'collected'
    collection(snap, 'org_policy_effective')['items'] = [{
        'constraint': 'iam.allowedPolicyMemberDomains',
        'spec': {'rules': [{'values': {'allowedValues': ['C1234']}}]}}]
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))


def test_cross_project_service_account_requires_explicit_attachment_policy():
    snap = report()
    remote_email = 'runner@p2.iam.gserviceaccount.com'
    remote_sa = 'serviceAccount:' + remote_email
    for row in snap['collections']:
        for item in row['items']:
            if row['type'] == 'service_account':
                item['email'] = remote_email
                item['projectId'] = 'p2'
                item['iamPolicy']['bindings'].append({
                    'role': 'roles/iam.serviceAccountUser', 'members': [CALLER]})
                row['scope'] = OTHER
            elif row['type'] == 'iam_policy':
                for binding in item['bindings']:
                    binding['members'] = [remote_sa if member == SA else member
                                          for member in binding['members']]
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))
    snap['collections'].append({'type': 'org_policy_effective', 'scope': OTHER,
                                'status': 'collected', 'items': [{
                                    'constraint': 'iam.disableCrossProjectServiceAccountUsage',
                                    'spec': {'rules': [{'enforce': False}]}}]})
    assert paths(snap) == [(
        'gcp_verified_authority:dataform_workflow:' + remote_sa, 'conditional')]
    collection(snap, 'org_policy_effective', OTHER)['items'][0]['spec']['rules'][0]['enforce'] = True
    assert not any(confidence == 'conditional' for _, confidence in paths(snap))
