from peaso.least_privilege_permissions import enrich, grant_groups

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


def test_policy_service_date_fills_missing_action_date_without_claiming_action_use():
    policy_arn = f'arn:aws:iam::{ACCOUNT}:policy/Operations'
    user = row('iam_user', {'Arn': ARN, 'AttachedManagedPolicies': [{'PolicyArn': policy_arn}]})
    policy = row('iam_policy', {'Arn': policy_arn, 'PolicyName': 'Operations',
        'ServicesLastAccessedStatus': {'collection_status': 'collected'},
        'ServicesLastAccessed': [{'ServiceNamespace': 'iam', 'LastAuthenticated': '2026-10-18T00:00:00Z'}],
        'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': 'iam:CreateAccessKey', 'Resource': '*'}]}})
    permission = enrich(card(), 'aws', [user, policy], NOW)['high_risk_permissions'][0]
    assert permission['group_key'] == policy_arn
    assert permission['usage_basis'] == 'policy'
    assert permission['days_since_last_access'] == 3
    assert not permission.get('unused_finding')


def test_aws_action_report_precedes_service_and_shared_policy_dates():
    policy_arn = f'arn:aws:iam::{ACCOUNT}:policy/Operations'
    user = row('iam_user', {'Arn': ARN, 'AttachedManagedPolicies': [{'PolicyArn': policy_arn}],
        'ServicesLastAccessedStatus': {'collection_status': 'collected'},
        'ServicesLastAccessed': [{'ServiceNamespace': 'iam', 'LastAuthenticated': '2026-10-20T00:00:00Z',
            'TrackedActionsLastAccessed': [{'ActionName': 'CreateAccessKey', 'LastAccessedTime': '2026-10-15T00:00:00Z'}]}]})
    policy = row('iam_policy', {'Arn': policy_arn, 'PolicyName': 'Operations',
        'ServicesLastAccessedStatus': {'collection_status': 'collected'},
        'ServicesLastAccessed': [{'ServiceNamespace': 'iam', 'LastAuthenticated': '2026-10-19T00:00:00Z',
            'TrackedActionsLastAccessed': [{'ActionName': 'CreateAccessKey', 'LastAccessedTime': '2026-10-18T00:00:00Z'}]}],
        'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': 'iam:CreateAccessKey', 'Resource': '*'}]}})
    permission = enrich(card(), 'aws', [user, policy], NOW)['high_risk_permissions'][0]
    assert permission['usage_basis'] == 'permission'
    assert permission['last_accessed'] == '2026-10-15T00:00:00Z'
    assert permission['days_since_last_access'] == 6
    user['data'].pop('ServicesLastAccessed')
    permission = enrich(card(), 'aws', [user, policy], NOW)['high_risk_permissions'][0]
    assert permission['usage_basis'] == 'policy'
    assert permission['last_accessed'] == '2026-10-18T00:00:00Z'


def test_aws_action_not_observed_is_distinct_from_service_use():
    user = row('iam_user', {'Arn': ARN, 'UserPolicyList': [{'PolicyDocument': {'Statement': [
        {'Effect': 'Allow', 'Action': 'iam:CreateAccessKey', 'Resource': '*'}]}}],
        'ServicesLastAccessedStatus': {'collection_status': 'collected',
            'job_completion_date': '2026-10-20T00:00:00Z'},
        'ServicesLastAccessed': [{'ServiceNamespace': 'iam', 'LastAuthenticated': '2026-10-19T00:00:00Z',
            'TrackedActionsUnobserved': ['CreateAccessKey']}]})
    permission = enrich(card(), 'aws', [user], NOW)['high_risk_permissions'][0]
    assert permission['usage_status'] == 'not_observed'
    assert permission['usage_basis'] == 'service'
    assert permission['days_since_last_access'] == 2


def test_aws_report_is_indexed_once_for_multiple_permissions():
    class CountingServices(list):
        reads = 0

        def __iter__(self):
            self.reads += 1
            return super().__iter__()

    services = CountingServices([{'ServiceNamespace': 'iam',
        'TrackedActionsLastAccessed': [
            {'ActionName': 'CreateAccessKey', 'LastAccessedTime': '2026-10-18T00:00:00Z'},
            {'ActionName': 'PassRole', 'LastAccessedTime': '2026-10-19T00:00:00Z'}]}])
    user = row('iam_user', {'Arn': ARN,
        'UserPolicyList': [{'PolicyDocument': {'Statement': [
            {'Effect': 'Allow', 'Action': ['iam:CreateAccessKey', 'iam:PassRole'], 'Resource': '*'}]}}],
        'ServicesLastAccessedStatus': {'collection_status': 'collected'},
        'ServicesLastAccessed': services})
    permissions = enrich(card(), 'aws', [user], NOW)['high_risk_permissions']
    assert {permission['permission'] for permission in permissions} == {'iam:CreateAccessKey', 'iam:PassRole'}
    assert all(permission['usage_basis'] == 'permission' for permission in permissions)
    assert services.reads == 1


def test_unused_filter_fact_requires_exact_access_analyzer_action_finding():
    user = row('iam_user', {'Arn': ARN, 'UserPolicyList': [{'PolicyName': 'key-admin',
        'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': 'iam:CreateAccessKey', 'Resource': '*'}]}}]})
    finding = {'kind': 'permission', 'value': 'iam:CreateAccessKey',
        'source': 'AWS IAM Access Analyzer unused access', 'confidence': 'provider_recommendation'}
    permission = enrich(dict(card(), suggestions=[finding]), 'aws', [user], NOW)['high_risk_permissions'][0]
    assert permission['unused_finding'] is True
    assert 'last_accessed' not in permission
    wildcard = row('iam_user', {'Arn': ARN, 'PolicyDocument': {'Statement': [
        {'Effect': 'Allow', 'Action': 'iam:*', 'Resource': '*'}]}})
    assert not enrich(dict(card(), suggestions=[finding]), 'aws', [wildcard], NOW)['high_risk_permissions'][0].get('unused_finding')


def test_grouped_policy_collects_distinct_principals_and_their_grants():
    policy_arn = f'arn:aws:iam::{ACCOUNT}:policy/Operations'
    second = f'arn:aws:iam::{ACCOUNT}:user/Bob'
    users = [row('iam_user', {'Arn': principal, 'AttachedManagedPolicies': [{'PolicyArn': policy_arn}]})
             for principal in (ARN, second)]
    policy = row('iam_policy', {'Arn': policy_arn, 'PolicyName': 'Operations',
        'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': 'iam:CreateAccessKey', 'Resource': '*'}]}})
    groups = grant_groups([card(), dict(card(), id=second, principal=second)], 'aws', [*users, policy], NOW)
    assert len(groups) == 1
    assert groups[0]['id'] == policy_arn
    assert len(groups[0]['principals']) == 2
    assert groups[0]['permission_count'] == 2


def test_gcp_insight_and_audit_distinguish_window_from_exact_last_use():
    member = 'user:alice@example.test'
    value = {'id': member, 'principal': member, 'suggestions': []}
    role = 'projects/p/roles/operations'
    permission = 'iam.serviceAccounts.getAccessToken'
    rows = [row('iam_policy', {'bindings': [{'role': role, 'members': [member]}]}, 'projects/p'),
        row('iam_role', {'name': role, 'includedPermissions': [permission]}, 'projects/p'),
        row('insight', {'insightSubtype': 'PERMISSIONS_USAGE', 'stateInfo': {'state': 'ACTIVE'},
            'content': {'member': member, 'role': role, 'exercisedPermissions': []},
            'lastRefreshTime': '2026-10-20T00:00:00Z', 'observationPeriod': '7776000s'}, 'projects/p')]
    candidate = enrich(value, 'gcp', rows, NOW)['high_risk_permissions'][0]
    assert candidate['usage_status'] == 'not_observed'
    assert candidate['usage_window_days'] == 90
    assert 'last_accessed' not in candidate
    rows.append(row('activity', {'principalEmail': 'alice@example.test', 'timestamp': '2026-10-20T12:00:00Z',
        'statusCode': 0, 'authorizationInfo': [{'permission': permission, 'granted': True}]}, 'projects/p'))
    observed = enrich(value, 'gcp', rows, NOW)['high_risk_permissions'][0]
    assert observed['usage_status'] == 'observed'
    assert observed['usage_basis'] == 'permission'
    assert observed['days_since_last_access'] == 0
    assert observed['usage_source'] == 'GCP Cloud Audit Logs'
    rows[-2]['data']['content']['exercisedPermissions'] = [{'permission': permission}]
    assert enrich(value, 'gcp', rows[:-1], NOW)['high_risk_permissions'][0]['usage_status'] == 'observed'
    rows[-2]['data']['content']['condition'] = {'expression': 'resource.name == "other"'}
    assert 'usage_status' not in enrich(value, 'gcp', rows[:-1], NOW)['high_risk_permissions'][0]


def test_azure_activity_requires_matching_caller_action_success_and_scope():
    target = '12345678-1234-1234-1234-123456789012'
    value = {'id': target, 'principal': target, 'suggestions': []}
    scope = '/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    action = 'Microsoft.Authorization/roleAssignments/write'
    definition = row('role_definition', {'name': '/providers/Microsoft.Authorization/roleDefinitions/owner',
        'properties': {'roleName': 'Owner', 'permissions': [{'actions': [action]}]}}, scope)
    assignment = row('role_assignment', {'properties': {'principalId': target,
        'roleDefinitionId': '/providers/Microsoft.Authorization/roleDefinitions/owner', 'scope': scope}}, scope)
    event = {'caller': target, 'eventTimestamp': '2026-10-20T12:00:00Z',
        'status': {'value': 'Succeeded'}, 'operationName': {'value': 'Microsoft.Resources/deployments/write'},
        'authorizationAction': action,
        'resourceId': scope + '/resourceGroups/app'}
    rows = [definition, assignment, row('activity_log', event, scope)]
    observed = enrich(value, 'azure', rows, NOW)['high_risk_permissions'][0]
    assert observed['usage_basis'] == 'permission' and observed['days_since_last_access'] == 0
    rows[-1]['data']['caller'] = 'some display name'
    rows[-1]['data']['principalObjectId'] = target
    assert enrich(value, 'azure', rows, NOW)['high_risk_permissions'][0]['usage_basis'] == 'permission'
    rows[-1]['data']['caller'] = target
    rows[-1]['data']['authorizationAction'] = 'Microsoft.Resources/deployments/write'
    assert 'last_accessed' not in enrich(value, 'azure', rows, NOW)['high_risk_permissions'][0]
    rows[-1]['data']['authorizationAction'] = action
    rows[-1]['data']['resourceId'] = scope + '-foreign/resourceGroups/app'
    assert 'last_accessed' not in enrich(value, 'azure', rows, NOW)['high_risk_permissions'][0]


def test_azure_wildcard_uses_only_compatible_management_action():
    target = '12345678-1234-1234-1234-123456789012'
    scope = '/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    value = {'id': target, 'principal': target, 'suggestions': []}
    definition = row('role_definition', {'name': '/providers/Microsoft.Authorization/roleDefinitions/owner',
        'properties': {'roleName': 'Owner', 'permissions': [{'actions': ['Microsoft.Authorization/*'],
            'notActions': ['Microsoft.Authorization/roleAssignments/delete'],
            'dataActions': ['Microsoft.Authorization/*']}]}}, scope)
    assignment = row('role_assignment', {'properties': {'principalId': target,
        'roleDefinitionId': '/providers/Microsoft.Authorization/roleDefinitions/owner', 'scope': scope}}, scope)
    event = row('iam_usage_activity', {'caller': target, 'eventTimestamp': '2026-10-20T12:00:00Z',
        'status': {'value': 'Succeeded'}, 'authorizationAction': 'Microsoft.Authorization/roleAssignments/write',
        'resourceId': scope + '/resourceGroups/app'}, scope)
    permissions = enrich(value, 'azure', [definition, assignment, event], NOW)['high_risk_permissions']
    management = next(p for p in permissions if p['exclusions'])
    data = next(p for p in permissions if not p['exclusions'])
    assert management['usage_basis'] == 'compatible'
    assert 'last_accessed' not in data
    event['data']['authorizationAction'] = 'Microsoft.Authorization/roleAssignments/delete'
    assert all('last_accessed' not in p for p in enrich(value, 'azure', [definition, assignment, event], NOW)['high_risk_permissions'])


def test_grouping_builds_usage_index_once_for_all_principals(monkeypatch):
    import peaso.least_privilege_permissions as usage
    original = usage._usage_index
    calls = []
    def once(provider, rows):
        calls.append((provider, len(rows)))
        return original(provider, rows)
    monkeypatch.setattr(usage, '_usage_index', once)
    rows = [row('iam_user', {'Arn': ARN, 'UserPolicyList': [{'PolicyName': 'p',
        'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': '*'}]}}]})]
    cards = [card(), dict(card(), id='other', principal=f'arn:aws:iam::{ACCOUNT}:user/Bob')]
    grant_groups(cards, 'aws', rows, NOW)
    assert calls == [('aws', 1)]
