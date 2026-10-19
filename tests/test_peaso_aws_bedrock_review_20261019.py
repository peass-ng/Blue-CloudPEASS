"""Bedrock metadata producer/consumer contracts; no cloud calls or invocation."""
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from peaso.checks import aws_bedrock_review_20261019 as checks
from peaso.collectors import aws_bedrock_security_metadata as collector
from peaso.collectors.aws import ReadResult
from tests.test_peaso_collectors_aws import sdk  # existing scoped boto Stubber fixture

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
ROLE = 'arn:aws:iam::' + ACCOUNT + ':role/agent'
ROLE2 = 'arn:aws:iam::' + ACCOUNT + ':role/other'
STAMP = datetime(2026, 10, 19, tzinfo=timezone.utc)


def agent(identifier='ABCDEFGHIJ', role=ROLE, region=REGION):
    return {'agentId': identifier, 'AgentRoleMetadata': {
        'agentId': identifier, 'agentArn': f'arn:aws:bedrock:{region}:{ACCOUNT}:agent/{identifier}',
        'agentVersion': 'DRAFT', 'agentResourceRoleArn': role, 'collection_status': 'collected'},
        'DeployedRoleVersions': {'collection_status': 'empty', 'items': []}}


def principal(role=True, document=None):
    row = {'Arn': ROLE if role else f'arn:aws:iam::{ACCOUNT}:user/alice',
           'AttachedManagedPolicies': [], 'RolePolicyList' if role else 'UserPolicyList': [],
           '_provenance': {'operation': 'iam:GetAccountAuthorizationDetails', 'native_response_complete': True}}
    if role:
        row['PermissionsBoundary'] = {'PermissionsBoundaryType': 'PermissionsBoundaryPolicy',
                                     'PermissionsBoundaryArn': f'arn:aws:iam::{ACCOUNT}:policy/boundary'}
    else:
        row['UserName'] = 'alice'
    if document is not None:
        row['RolePolicyList' if role else 'UserPolicyList'] = [{'PolicyName': 'inline', 'PolicyDocument': document}]
    return row


def doc(action='s3:GetObject', effect='Allow', **extra):
    return {'Statement': [{'Effect': effect, 'Action': action, 'Resource': '*', **extra}]}


def index(kind, rows, status='collected'):
    return {'context': {'scope': SCOPE}, 'collections': {kind: [{
        'type': kind, 'scope': ACCOUNT + '/global', 'account_id': ACCOUNT, 'global': True,
        'status': status, 'items': rows}]}}


def credential():
    return {'ServiceName': 'bedrock.amazonaws.com', 'ServiceSpecificCredentialId': 'ACCAEXAMPLE', 'UserName': 'alice'}


@pytest.mark.parametrize('document,expected', [(doc(), 'PASS'), (doc('*'), 'FAIL'),
    (doc('iam:CreatePolicyVersion'), 'FAIL'), (doc('bedrock:*'), 'FAIL'),
    (doc('bedrock:InvokeModel'), 'PASS'), ({'Statement': []}, 'PASS'),
    ({'Statement': [{'Effect': 'Allow', 'Resource': '*'}]}, 'UNKNOWN')])
def test_key_owner_static_policy_truths(document, expected):
    item, scoped = credential(), index('iam_user', [principal(False, document)])
    before = deepcopy((item, scoped))
    status, evidence = checks.api_key_no_administrative_privileges(item, scoped)
    assert status == expected
    assert evidence.get('observed') and (item, scoped) == before


@pytest.mark.parametrize('document,expected', [(doc(), 'PASS'), (doc('*'), 'FAIL'),
    (doc('iam:CreatePolicyVersion'), 'FAIL'), ({'Statement': []}, 'PASS')])
def test_agent_role_static_policy_truths(document, expected):
    assert checks.agent_role_least_privilege(agent(), index('iam_role', [principal(True, document)]))[0] == expected


@pytest.mark.parametrize('status', ['denied', 'partial', 'unknown', 'not_collected', 'malformed'])
def test_policy_inventory_failure_never_produces_pass(status):
    assert checks.agent_role_least_privilege(agent(), index('iam_role', [principal()], status))[0] == 'UNKNOWN'
    assert checks.api_key_no_administrative_privileges(credential(), index('iam_user', [principal(False)], status))[0] == 'UNKNOWN'


def test_unresolved_attached_policy_and_boundary_coverage_stay_unknown():
    role = principal()
    role['AttachedManagedPolicies'] = [{'PolicyArn': f'arn:aws:iam::{ACCOUNT}:policy/missing'}]
    assert checks.agent_role_least_privilege(agent(), index('iam_role', [role]))[0] == 'UNKNOWN'
    role = principal()
    role['_coverage'] = {'PermissionsBoundary': {'status': 'denied'}}
    assert checks.agent_role_least_privilege(agent(), index('iam_role', [role]))[0] == 'UNKNOWN'
    role = principal()
    del role['PermissionsBoundary']
    assert checks.agent_role_least_privilege(agent(), index('iam_role', [role]))[0] == 'FAIL'
    role = principal()
    role['AttachedManagedPolicies'] = [{'PolicyArn': 'arn:aws:iam::aws:policy/AmazonS3FullAccess'}]
    assert checks.agent_role_least_privilege(agent(), index('iam_role', [role]))[0] == 'FAIL'


def test_managed_policy_default_document_requires_complete_unambiguous_resolution():
    user = principal(False)
    arn = f'arn:aws:iam::{ACCOUNT}:policy/managed'
    user['AttachedManagedPolicies'] = [{'PolicyArn': arn}]
    scoped = index('iam_user', [user])
    scoped['collections'].update(index('iam_policy', [{'Arn': arn, 'PolicyVersionList': [
        {'IsDefaultVersion': True, 'Document': doc('bedrock:*')}]}])['collections'])
    assert checks.api_key_no_administrative_privileges(credential(), scoped)[0] == 'FAIL'
    scoped['collections']['iam_policy'][0]['items'][0]['PolicyVersionList'][0]['IsDefaultVersion'] = False
    assert checks.api_key_no_administrative_privileges(credential(), scoped)[0] == 'UNKNOWN'


def proof_index(agents=None):
    proof = {'AccountId': ACCOUNT, 'profile': checks.PROFILE,
             'EnabledRegions': {'collection_status': 'collected', 'items': [{'RegionName': REGION}]},
             'RegionAgents': [{'Region': REGION, 'Agents': {'collection_status': 'collected', 'items': agents or [agent()]}}]}
    return index('bedrock_agent_account_inventory', [proof])


def test_dedication_requires_complete_account_region_and_deployed_version_reads():
    item, scoped = agent(), proof_index()
    before = deepcopy((item, scoped))
    assert checks.agent_role_not_shared_across_agents(item, scoped)[0] == 'PASS'
    assert (item, scoped) == before
    envelope = scoped['collections']['bedrock_agent_account_inventory'][0]
    envelope['status'] = 'partial'
    assert checks.agent_role_not_shared_across_agents(item, scoped)[0] == 'UNKNOWN'
    scoped = proof_index()
    scoped['collections']['bedrock_agent_account_inventory'][0]['items'][0]['RegionAgents'][0]['Agents']['items'][0]['DeployedRoleVersions']['collection_status'] = 'denied'
    assert checks.agent_role_not_shared_across_agents(item, scoped)[0] == 'UNKNOWN'


def test_observed_duplicate_survives_partial_inventory_and_missing_versions():
    other = agent('KLMNOPQRST')
    other['DeployedRoleVersions'] = {'collection_status': 'denied', 'items': []}
    scoped = proof_index([agent(), other])
    scoped['collections']['bedrock_agent_account_inventory'][0]['status'] = 'partial'
    status, evidence = checks.agent_role_not_shared_across_agents(agent(), scoped)
    assert status == 'FAIL' and evidence['inventory_complete'] is False


def test_cross_region_alias_routed_version_sharing_is_detected():
    other = agent('KLMNOPQRST', ROLE2, 'eu-west-1')
    other['DeployedRoleVersions'] = {'collection_status': 'collected', 'items': [
        {'agentVersion': '7', 'agentResourceRoleArn': ROLE}]}
    scoped = proof_index()
    proof = scoped['collections']['bedrock_agent_account_inventory'][0]['items'][0]
    proof['EnabledRegions']['items'].append({'RegionName': 'eu-west-1'})
    proof['RegionAgents'].append({'Region': 'eu-west-1', 'Agents': {'collection_status': 'collected', 'items': [other]}})
    assert checks.agent_role_not_shared_across_agents(agent(), scoped)[0] == 'FAIL'
    proof['RegionAgents'][1]['Agents']['items'][0]['AgentRoleMetadata']['agentResourceRoleArn'] = 'arn:aws:iam::999999999999:role/foreign'
    assert checks.agent_role_not_shared_across_agents(agent(), scoped)[0] == 'UNKNOWN'


def sdk_agent(version=False):
    data = {'agentId': 'ABCDEFGHIJ', 'agentName': 'example', 'agentArn': f'arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/ABCDEFGHIJ',
            'version' if version else 'agentVersion': '1' if version else 'DRAFT',
            'agentStatus': 'PREPARED', 'idleSessionTTLInSeconds': 600, 'agentResourceRoleArn': ROLE,
            'createdAt': STAMP, 'updatedAt': STAMP, 'instruction': 'PRIVATE_INSTRUCTION_SENTINEL' * 2}
    return data


@pytest.mark.parametrize('version', [False, True])
def test_sdk_validated_metadata_projection_discards_instruction_before_cache(version):
    operation = 'get_agent_version' if version else 'get_agent'
    field = 'agentVersion' if version else 'agent'
    args = {'agentId': 'ABCDEFGHIJ', **({'agentVersion': '1'} if version else {})}
    projected = collector.project_response({field: sdk_agent(version)}, 'bedrock-agent', operation, args)
    assert 'PRIVATE_INSTRUCTION_SENTINEL' not in repr(projected)
    assert projected[field]['agentResourceRoleArn'] == ROLE
    assert projected['_metadata_projection'] == collector.PROFILE


def test_account_collector_output_is_consumable_and_denial_cannot_be_pass():
    class Requests:
        def pages(self, session, service, region, operation, field, **kwargs):
            if operation == 'describe_regions': return ReadResult([{'RegionName': REGION}])
            if operation == 'list_agents': return ReadResult([{'agentId': 'ABCDEFGHIJ'}])
            if operation == 'list_agent_aliases': return ReadResult([], 'empty')
            raise AssertionError(operation)
        def detail(self, session, service, region, operation, **kwargs):
            assert kwargs['_metadata_profile'] == collector.PROFILE
            return {'collection_status': 'collected', 'agent': collector.project_response(
                {'agent': sdk_agent()}, service, operation, {'agentId': 'ABCDEFGHIJ'})['agent']}
    requests = Requests()
    read = collector.account_inventory(requests, object(), REGION, ACCOUNT)
    assert read.status == 'collected'
    assert checks.agent_role_not_shared_across_agents(agent(), index(collector.KIND, read.items, read.status))[0] == 'PASS'
    original = requests.pages
    requests.pages = lambda session, service, region, operation, field, **kw: (
        ReadResult([], 'denied', {'code': 'AccessDenied'}) if operation == 'list_agent_aliases' else
        original(session, service, region, operation, field, **kw))
    read = collector.account_inventory(requests, object(), REGION, ACCOUNT)
    assert read.status == 'partial'
    assert checks.agent_role_not_shared_across_agents(agent(), index(collector.KIND, read.items, read.status))[0] == 'UNKNOWN'


@pytest.mark.parametrize('aliases_denied,expected', [(False, 'PASS'), (True, 'UNKNOWN')])
def test_public_collect_metadata_feeds_role_predicate_without_prompt_material(sdk, aliases_denied, expected):
    from peaso.collectors import aws
    from peaso.snapshot import validate
    assert collector.KIND in aws.GLOBAL_TYPES, 'coordinator must wire the trusted extension before admission'
    _session, add, _clients = sdk
    add('sts').add_response('get_caller_identity', {
        'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'AIDAREVIEWER'}, {})
    add('ec2').add_response('describe_regions', {'Regions': [{'RegionName': REGION}]}, {'AllRegions': False})
    summary = {'agentId': 'ABCDEFGHIJ', 'agentName': 'example', 'agentStatus': 'PREPARED', 'updatedAt': STAMP,
               'guardrailConfiguration': {'guardrailIdentifier': 'abc123', 'guardrailVersion': '1'}}
    stub = add('bedrock-agent')
    stub.add_response('list_agents', {'agentSummaries': [summary]}, {})
    stub.add_response('get_agent', {'agent': sdk_agent()}, {'agentId': 'ABCDEFGHIJ'})
    if aliases_denied:
        stub.add_client_error('list_agent_aliases', 'AccessDeniedException', 'inert denial',
                              expected_params={'agentId': 'ABCDEFGHIJ'})
    else:
        stub.add_response('list_agent_aliases', {'agentAliasSummaries': []}, {'agentId': 'ABCDEFGHIJ'})
    stub.add_response('list_agents', {'agentSummaries': [summary]}, {})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'auth': {'profile': 'chosen'},
                            'options': {'regions': [REGION], 'service_concurrency': 1}},
                           [collector.KIND, 'bedrock_agent'])
    assert validate(snapshot) == snapshot
    assert 'PRIVATE_INSTRUCTION_SENTINEL' not in repr(snapshot)
    assert 'selected-secret-must-not-leak' not in repr(snapshot)
    proof = next(row for row in snapshot['collections'] if row['type'] == collector.KIND)
    agents = next(row for row in snapshot['collections'] if row['type'] == 'bedrock_agent')
    assert agents['status'] == 'collected' and agents['items'][0]['guardrailConfiguration'] == summary['guardrailConfiguration']
    scoped = index(collector.KIND, proof['items'], proof['status'])
    status, evidence = checks.agent_role_not_shared_across_agents(agents['items'][0], scoped)
    assert status == expected and len(evidence['observed']) <= 150


def test_runtime_fixtures_and_brief_copy_have_actual_truths():
    functions = [checks.agent_role_least_privilege, checks.agent_role_not_shared_across_agents,
                 checks.api_key_no_administrative_privileges]
    for cid, function in zip(checks.IDS, functions):
        cases = checks.RUNTIME_CASES[cid]
        for key, expected in [('pass', 'PASS'), ('fail', 'FAIL')]:
            status, evidence = function(deepcopy(cases[key]), deepcopy(cases[key + '_index']))
            assert status == expected and len(evidence['observed']) <= 150
        assert function({}, {})[0] == 'UNKNOWN'
        assert function(None, {})[0] == 'UNKNOWN'


def test_malformed_boundary_identity_and_context_cannot_pass():
    role = principal()
    role['PermissionsBoundary']['PermissionsBoundaryArn'] = ''
    assert checks.agent_role_least_privilege(agent(), index('iam_role', [role]))[0] == 'UNKNOWN'
    scoped = index('iam_user', [principal(False)])
    scoped['context']['scope'] = ACCOUNT + '/invalid'
    assert checks.api_key_no_administrative_privileges(credential(), scoped)[0] == 'UNKNOWN'
    item = credential()
    item['ServiceSpecificCredentialId'] = ''
    assert checks.api_key_no_administrative_privileges(item, index('iam_user', [principal(False)]))[0] == 'UNKNOWN'


def test_denied_partial_inventory_items_coverage_cannot_pass():
    scoped = proof_index()
    scoped['collections'][collector.KIND][0]['items'][0]['RegionAgents'][0]['Agents']['_coverage'] = {
        'items': {'status': 'denied'}}
    assert checks.agent_role_not_shared_across_agents(agent(), scoped)[0] == 'UNKNOWN'
