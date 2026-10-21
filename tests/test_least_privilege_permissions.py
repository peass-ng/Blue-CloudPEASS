from peaso.least_privilege_permissions import enrich

ACCOUNT = '123456789012'
SCOPE = ACCOUNT + '/global'
ARN = f'arn:aws:iam::{ACCOUNT}:user/Alice'
NOW = '2026-10-21T00:00:00Z'


def row(kind, data, scope=SCOPE, **extra):
    return dict(type=kind, scope=scope, data=data, **extra)


def card(**extra):
    return dict(id=ARN, principal=ARN, provider='aws', suggestions=[], **extra)


def test_complete_attached_and_group_permissions_keep_targets_and_usage_scope():
    role = row('iam_user', {'Arn': ARN, 'UserName': 'Alice', 'GroupList': ['Operators'],
        'ServicesLastAccessedStatus': {'collection_status': 'collected'},
        'ServicesLastAccessed': [{'ServiceNamespace': 'iam', 'LastAuthenticated': '2026-10-20T00:00:00Z'}],
        'UserPolicyList': [{'PolicyName': 'inline', 'PolicyDocument': {'Statement': [
            {'Effect': 'Allow', 'Action': ['iam:CreateAccessKey', 's3:ListBucket'], 'Resource': '*'},
            {'Effect': 'Deny', 'Action': 'iam:DeleteRole', 'Resource': '*'}]}}]})
    group = row('iam_group', {'GroupName': 'Operators', 'Arn': f'arn:aws:iam::{ACCOUNT}:group/Operators',
        'AttachedManagedPolicies': [{'PolicyArn': f'arn:aws:iam::{ACCOUNT}:policy/Operations'}]})
    policy = row('iam_policy', {'Arn': f'arn:aws:iam::{ACCOUNT}:policy/Operations', 'PolicyName': 'Operations',
        'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': f'arn:aws:iam::{ACCOUNT}:role/Target',
                                          'Condition': {'StringEquals': {'iam:PassedToService': 'lambda.amazonaws.com'}}}]}})
    hints = [{'kind': 'permission', 'value': 'iam:PassRole', 'confidence': 'provider_recommendation', 'last_accessed': '2026-01-01T00:00:00Z'}]
    result = enrich(dict(card(), suggestions=hints), 'aws', [role, group, policy], NOW)
    permissions = {p['permission']: p for p in result['high_risk_permissions']}
    assert 'iam:PassRole' in permissions and 'iam:CreateAccessKey' in permissions
    assert 's3:ListBucket' not in permissions and 'iam:DeleteRole' not in permissions
    inherited = permissions['iam:PassRole']
    assert inherited['source'] == 'Operators → Operations'
    assert inherited['resources'] == [f'arn:aws:iam::{ACCOUNT}:role/Target']
    assert inherited['conditions']['StringEquals']['iam:PassedToService'] == 'lambda.amazonaws.com'
    assert inherited['usage_basis'] == 'permission' and inherited['days_since_last_access'] > 90
    assert permissions['iam:CreateAccessKey']['usage_basis'] == 'service'
    assert permissions['iam:CreateAccessKey']['days_since_last_access'] == 1


def test_wildcard_is_not_marked_unused_from_one_unused_action_and_missing_usage_is_unknown():
    role = row('iam_user', {'Arn': ARN, 'UserPolicyList': [{'PolicyDocument': {'Statement': [
        {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}]})
    value = dict(card(), suggestions=[{'kind': 'permission', 'value': 'iam:PassRole', 'confidence': 'provider_recommendation', 'last_accessed': '2020-01-01T00:00:00Z'}])
    result = enrich(value, 'aws', [role], NOW)
    assert len(result['high_risk_permissions']) == 1
    permission = result['high_risk_permissions'][0]
    assert permission['permission'] == '*' and permission['resources'] == ['*']
    assert 'last_accessed' not in permission and 'days_since_last_access' not in permission


def test_no_truncation_and_no_cross_account_policy_resolution():
    source = row('iam_user', {'Arn': ARN, 'AttachedManagedPolicies': [{'PolicyArn': f'arn:aws:iam::{ACCOUNT}:policy/Operations'}],
        'UserPolicyList': [{'PolicyDocument': {'Statement': [
            {'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': f'arn:aws:iam::{ACCOUNT}:role/Target{i}'} for i in range(45)]}}]})
    foreign = row('iam_policy', {'Arn': f'arn:aws:iam::{ACCOUNT}:policy/Operations', 'PolicyDocument': {
        'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}, '999999999999/global')
    result = enrich(card(), 'aws', [source, foreign], NOW)
    assert len(result['high_risk_permissions']) == 45
    assert all(p['permission'] == 'iam:PassRole' for p in result['high_risk_permissions'])
    assert result['permission_definitions_missing'] == [f'arn:aws:iam::{ACCOUNT}:policy/Operations']


def test_azure_assignments_resolve_definition_and_retain_exclusions():
    value = {'id': 'principal', 'principal': 'principal', 'suggestions': []}
    rows = [row('role_definition', {'name': '/providers/Microsoft.Authorization/roleDefinitions/owner', 'properties': {
        'roleName': 'Owner', 'permissions': [{'actions': ['*'], 'notActions': ['Microsoft.Authorization/*/Delete']}]}}, '/'),
        row('role_assignment', {'properties': {'principalId': 'principal', 'roleDefinitionId': '/providers/Microsoft.Authorization/roleDefinitions/owner', 'scope': '/subscriptions/example'}}, '/subscriptions/example')]
    permissions = enrich(value, 'azure', rows, NOW)['high_risk_permissions']
    assert permissions[0]['permission'] == '*'
    assert permissions[0]['source'] == 'Owner'
    assert permissions[0]['exclusions'] == ['Microsoft.Authorization/*/Delete']


def test_gcp_only_collected_role_definitions_supply_permissions():
    value = {'id': 'user:alice@example.test', 'principal': 'user:alice@example.test', 'suggestions': []}
    rows = [row('iam_policy', {'bindings': [{'role': 'projects/p/roles/operations', 'members': [value['principal']]},
        {'role': 'roles/owner', 'members': [value['principal']]}]}, 'projects/p'),
        row('iam_role', {'name': 'projects/p/roles/operations', 'includedPermissions': ['iam.serviceAccounts.getAccessToken']}, 'projects/p')]
    result = enrich(value, 'gcp', rows, NOW)
    assert [p['permission'] for p in result['high_risk_permissions']] == ['iam.serviceAccounts.getAccessToken']
    assert result['permission_definitions_missing'] == ['roles/owner']


def test_kubernetes_role_binding_is_cluster_and_namespace_bound():
    value = {'id': 'cluster-one|system:serviceaccount:app:worker', 'principal': 'system:serviceaccount:app:worker', 'suggestions': []}
    rows = [row('clusterrole', {'metadata': {'name': 'admin'}, 'rules': [{'verbs': ['*'], 'resources': ['*'], 'apiGroups': ['*']}]}, 'cluster-one/app'),
        row('rolebinding', {'metadata': {'name': 'grant', 'namespace': 'app'}, 'roleRef': {'kind': 'ClusterRole', 'name': 'admin'},
            'subjects': [{'kind': 'ServiceAccount', 'namespace': 'app', 'name': 'worker'}]}, 'cluster-one/app')]
    result = enrich(value, 'k8s', rows, NOW)
    assert result['high_risk_permissions']
    assert result['high_risk_permissions'][0]['source'] == 'ClusterRole admin'
    assert not enrich(dict(value, id='other-cluster|' + value['principal']), 'k8s', rows, NOW)['high_risk_permissions']


def test_inherited_only_aws_and_custom_gcp_permissions_are_listed_as_principals():
    from peaso.least_privilege import project
    rows = [row('iam_user', {'Arn': ARN, 'UserName': 'Alice', 'GroupList': ['Operators']}),
            row('iam_group', {'Arn': f'arn:aws:iam::{ACCOUNT}:group/Operators', 'GroupName': 'Operators', 'GroupPolicyList': [
                {'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}]})]
    aws = project('aws', rows)
    assert aws['items'][0]['principal'] == ARN
    assert aws['items'][0]['severity'] in {'critical', 'high'}
    rows = [row('iam_policy', {'bindings': [{'role': 'projects/p/roles/custom', 'members': ['user:alice@example.test']}]}, 'projects/p'),
            row('iam_role', {'name': 'projects/p/roles/custom', 'includedPermissions': ['iam.serviceAccounts.getAccessToken']}, 'projects/p')]
    gcp = project('gcp', rows)
    assert gcp['items'][0]['principal'] == 'user:alice@example.test'
    assert gcp['items'][0]['severity'] in {'critical', 'high'}
