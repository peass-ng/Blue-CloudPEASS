"""New native chain through actual SDK models/Requests; no inference/network."""
from datetime import datetime, timezone
from copy import deepcopy
from types import SimpleNamespace
import json
import pytest

from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live, aws_bedrock_reasoning_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector
from peaso.snapshot import make_snapshot

CHECK = 'aws_bedrock_automated_reasoning_policy_attached'
AGENT, ALIAS, GUARD = 'A1B2C3D4E5', 'ABCDEFGHIJ', 'abc123def456'
BASE = f'arn:aws:bedrock:{REGION}:{ACCOUNT}:'
AGENT_ARN, ALIAS_ARN, GUARD_ARN = BASE + 'agent/' + AGENT, BASE + f'agent-alias/{AGENT}/{ALIAS}', BASE + 'guardrail/' + GUARD
POLICY_ID, OTHER_ID = 'a1b2c3d4e5f6', 'b1c2d3e4f5g6'
POLICY, OTHER = BASE + 'automated-reasoning-policy/' + POLICY_ID + ':1', BASE + 'automated-reasoning-policy/' + OTHER_ID + ':2'
STAMP = datetime(2026, 10, 16, tzinfo=timezone.utc)
PRIVATE = 'NEVER_FOLLOW_SECRET_NEVER_COPY_PRIVATE_KEY'


def fixtures(mode):
    agents = {'agentSummaries': [{'agentId': AGENT, 'agentName': PRIVATE, 'agentStatus': 'PREPARED', 'updatedAt': STAMP}]}
    aliases = {'agentAliasSummaries': [{'agentAliasId': ALIAS, 'agentAliasName': PRIVATE,
        'agentAliasStatus': 'PREPARED', 'createdAt': STAMP, 'updatedAt': STAMP}]}
    alias = {'agentAlias': {'agentId': AGENT, 'agentAliasId': ALIAS, 'agentAliasName': PRIVATE,
        'agentAliasArn': ALIAS_ARN, 'agentAliasStatus': 'PREPARED', 'routingConfiguration': [{'agentVersion': '1'}],
        'createdAt': STAMP, 'updatedAt': STAMP, 'clientToken': PRIVATE, 'description': PRIVATE}}
    version = {'agentVersion': {'agentId': AGENT, 'agentName': PRIVATE, 'agentArn': AGENT_ARN, 'version': '1',
        'agentStatus': 'PREPARED', 'idleSessionTTLInSeconds': 600, 'agentResourceRoleArn': f'arn:aws:iam::{ACCOUNT}:role/Agent',
        'createdAt': STAMP, 'updatedAt': STAMP, 'instruction': PRIVATE,
        'promptOverrideConfiguration': {'promptConfigurations': [{'promptType': 'ORCHESTRATION',
            'promptCreationMode': 'OVERRIDDEN', 'basePromptTemplate': PRIVATE}]},
        'guardrailConfiguration': {'guardrailIdentifier': GUARD, 'guardrailVersion': '1'}}}
    guardrail = {'name': PRIVATE, 'guardrailId': GUARD, 'guardrailArn': GUARD_ARN, 'version': '1', 'status': 'READY',
        'createdAt': STAMP, 'updatedAt': STAMP, 'blockedInputMessaging': PRIVATE, 'blockedOutputsMessaging': PRIVATE,
        'wordPolicy': {'words': [{'text': PRIVATE}]}, 'automatedReasoningPolicy': {'policies': [POLICY]}}
    if mode == 'empty_agents': agents['agentSummaries'] = []
    if mode == 'empty_aliases': aliases['agentAliasSummaries'] = []
    if mode == 'agent_partial': agents['nextToken'] = 'next-agents'
    if mode == 'alias_partial': aliases['nextToken'] = 'next-aliases'
    if mode == 'draft_route': alias['agentAlias']['routingConfiguration'][0]['agentVersion'] = 'DRAFT'
    if mode == 'foreign_alias': alias['agentAlias']['agentAliasArn'] = ALIAS_ARN.replace(ACCOUNT, '999999999999')
    if mode == 'foreign_version': version['agentVersion']['agentArn'] = AGENT_ARN.replace(ACCOUNT, '999999999999')
    if mode == 'missing_binding': version['agentVersion'].pop('guardrailConfiguration')
    if mode == 'draft_guardrail': version['agentVersion']['guardrailConfiguration']['guardrailVersion'] = 'DRAFT'
    if mode == 'guardrail_transient': guardrail['status'] = 'UPDATING'
    if mode == 'foreign_guardrail': guardrail['guardrailArn'] = GUARD_ARN.replace(ACCOUNT, '999999999999')
    if mode == 'foreign_policy': guardrail['automatedReasoningPolicy']['policies'] = [POLICY.replace(ACCOUNT, '999999999999')]
    if mode == 'none_policy': guardrail.pop('automatedReasoningPolicy')
    if mode in ('two_pass', 'second_missing', 'second_denied'): guardrail['automatedReasoningPolicy']['policies'].append(OTHER)
    return agents, aliases, alias, version, guardrail


def queue(sdk, mode, *, hosted=False):
    session, add = sdk; agent, bedrock = add('bedrock-agent'), add('bedrock')
    stubs, expected = [agent, bedrock], [0]
    def response(stub, operation, value, arguments):
        stub.add_response(operation, value, arguments); expected[0] += 1
    def denied(stub, operation, arguments):
        stub.add_client_error(operation, 'AccessDeniedException', expected_params=arguments); expected[0] += 1
    if hosted:
        sts = add('sts'); stubs.append(sts)
        response(sts, 'get_caller_identity', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'reviewer'}, {})
    agents, aliases, alias, version, guardrail = fixtures(mode)
    response(agent, 'list_agents', agents, {})
    if mode in ('empty_agents', 'agent_partial'): return session, stubs, expected[0]
    response(agent, 'list_agent_aliases', aliases, {'agentId': AGENT})
    if mode in ('empty_aliases', 'alias_partial'): return session, stubs, expected[0]
    args = {'agentId': AGENT, 'agentAliasId': ALIAS}
    if mode == 'alias_denied': denied(agent, 'get_agent_alias', args); return session, stubs, expected[0]
    response(agent, 'get_agent_alias', alias, args)
    if mode in ('foreign_alias', 'draft_route'): return session, stubs, expected[0]
    args = {'agentId': AGENT, 'agentVersion': '1'}
    if mode == 'version_denied': denied(agent, 'get_agent_version', args); return session, stubs, expected[0]
    response(agent, 'get_agent_version', version, args)
    if mode in ('foreign_version', 'missing_binding', 'draft_guardrail'): return session, stubs, expected[0]
    args = {'guardrailIdentifier': GUARD, 'guardrailVersion': '1'}
    if mode == 'guardrail_denied': denied(bedrock, 'get_guardrail', args); return session, stubs, expected[0]
    response(bedrock, 'get_guardrail', guardrail, args)
    if mode in ('guardrail_transient', 'foreign_guardrail', 'foreign_policy', 'none_policy'): return session, stubs, expected[0]
    for arn in guardrail['automatedReasoningPolicy']['policies']:
        args = {'policyArn': arn}
        if mode == 'one_missing' or mode == 'second_missing' and arn == OTHER:
            bedrock.add_client_error('get_automated_reasoning_policy', 'ResourceNotFoundException', expected_params=args)
            expected[0] += 1; continue
        if mode == 'policy_denied' or mode == 'second_denied' and arn == OTHER:
            denied(bedrock, 'get_automated_reasoning_policy', args); continue
        pid, v = arn.rsplit('/', 1)[1].split(':')
        policy = {'policyArn': arn.rsplit(':', 1)[0] if mode == 'policy_base_arn' else arn,
            'policyId': pid, 'name': PRIVATE, 'version': '99' if mode == 'mismatch_policy_version' else v,
            'definitionHash': 'a' * 128, 'updatedAt': STAMP, 'description': PRIVATE}
        response(bedrock, 'get_automated_reasoning_policy', policy, args)
    return session, stubs, expected[0]


CASES = [('pass', 'PASS'), ('two_pass', 'PASS'), ('none_policy', 'FAIL'), ('one_missing', 'FAIL'),
    ('second_missing', 'FAIL'), ('policy_denied', 'UNKNOWN'), ('second_denied', 'UNKNOWN'),
    ('alias_denied', 'UNKNOWN'), ('version_denied', 'UNKNOWN'), ('guardrail_denied', 'UNKNOWN'),
    ('missing_binding', 'UNKNOWN'), ('draft_route', 'UNKNOWN'), ('draft_guardrail', 'UNKNOWN'),
    ('guardrail_transient', 'UNKNOWN'), ('foreign_alias', 'UNKNOWN'), ('foreign_version', 'UNKNOWN'),
    ('foreign_guardrail', 'UNKNOWN'), ('foreign_policy', 'UNKNOWN'), ('mismatch_policy_version', 'UNKNOWN'),
    ('policy_base_arn', 'PASS'), ('agent_partial', 'UNKNOWN'), ('alias_partial', 'UNKNOWN'),
    ('empty_agents', 'UNKNOWN'), ('empty_aliases', 'UNKNOWN')]


@pytest.mark.parametrize('mode,expected', CASES)
def test_actual_sdk_requests_collect_engine(sdk, mode, expected):
    session, stubs, calls = queue(sdk, mode)
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1,
                          **({'max_pages': 1} if mode.endswith('_partial') else {})})
    read = native.collect(reader, session, REGION, ACCOUNT)
    scope = ACCOUNT + '/' + REGION
    # collect_live.append adds this stable identity before sealing a snapshot.
    # Direct fetcher tests perform the same projection, not a weaker evaluator.
    items = [{**row, 'id': row['_resource_id']} for row in read.items]
    snapshot = make_snapshot('aws', [scope], [{'type': native.KIND, 'scope': scope, 'service': 'bedrock',
        'status': read.status, 'items': items, **({'error': read.error} if read.error else {})}])
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert findings and all(f['status'] == expected for f in findings), findings
    assert reader.calls == calls
    assert PRIVATE not in json.dumps(snapshot, default=str)
    for future in reader._cache.values():
        assert len(next(key for key, value in reader._cache.items() if value is future)) == 6
        if future.exception() is None: assert PRIVATE not in json.dumps(future.result(), default=str)
        else: assert future.exception().__traceback__ is None and future.exception().__context__ is None
    if expected == 'PASS': assert findings[0]['evidence']['policy_resolution_semantics'] == 'published-policy-version-resolved'
    for stub in stubs: stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode,expected', [('pass', 'PASS'), ('none_policy', 'FAIL'), ('policy_denied', 'UNKNOWN')])
def test_normal_cognito_connector_plan_and_public_collector(monkeypatch, sdk, mode, expected):
    session, stubs, calls = queue(sdk, mode, hosted=True)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    auth = {'method': 'access_keys', 'aws_access_key_id': 'AKIA' + 'A' * 16, 'aws_secret_access_key': 'A' * 40}
    options = {'service_concurrency': 1, 'retries': 1}
    validate_connector('aws', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'auth': auth, 'options': options}
    required = plan_collection({'connector': connector, 'checks': [CHECK]})
    assert required == [native.KIND]
    snapshot = collect_live(connector, required)
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert findings and all(f['status'] == expected for f in findings)
    assert snapshot['metadata']['calls'] == calls and PRIVATE not in json.dumps(snapshot, default=str)
    for stub in stubs: stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['null_agent_guardrail', 'null_reasoning_policy', 'missing_agent_role', 'missing_guardrail_messages'])
def test_previous_hold_shapes_rejected_before_projection(mode):
    _, _, _, version, guardrail = fixtures('pass')
    if mode.startswith('null_agent') or mode == 'missing_agent_role':
        response, service, operation = version, 'bedrock-agent', 'get_agent_version'
        arguments = {'agentId': AGENT, 'agentVersion': '1'}
        if mode == 'null_agent_guardrail': response['agentVersion']['guardrailConfiguration'] = None
        else: response['agentVersion'].pop('agentResourceRoleArn')
    else:
        response, service, operation = guardrail, 'bedrock', 'get_guardrail'
        arguments = {'guardrailIdentifier': GUARD, 'guardrailVersion': '1'}
        if mode == 'null_reasoning_policy': response['automatedReasoningPolicy'] = None
        else: response.pop('blockedInputMessaging')
    original = deepcopy(response)
    with pytest.raises(aws.ReadFailure) as error:
        native.project_response(response, service, operation, arguments)
    assert error.value.status == 'malformed' and response == original


def test_captured_native_binding_rejects_rebinding_and_legacy_status_shortcuts(sdk):
    session, stubs, calls = queue(sdk, 'pass')
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1})
    read = native.collect(reader, session, REGION, ACCOUNT)
    assert read.status == 'collected' and reader.calls == calls
    for mode in ('binding_unavailable', 'foreign_guardrail', 'wrong_version', 'missing_resolution', 'foreign_partition', 'forged_absence'):
        row = deepcopy(read.items[0])
        if mode == 'binding_unavailable': row.update({'NativeBinding': 'unavailable', 'PolicyStatus': 'ACTIVE'})
        elif mode == 'foreign_guardrail': row['NativeGuardrailArn'] = GUARD_ARN.replace(ACCOUNT, '999999999999')
        elif mode == 'wrong_version': row['PolicyResolutions'][0]['NativePolicyVersion'] = '2'
        elif mode == 'missing_resolution': row['PolicyResolutions'] = []
        elif mode == 'foreign_partition': row['NativePartition'] = 'aws-cn'
        else: row['PolicyResolutions'] = [{'PolicyVersionArn': POLICY, 'Resolution': 'not_found', 'NativeErrorCode': 'AccessDeniedException'}]
        assert native.assess(row, ACCOUNT, REGION)[0] == 'UNKNOWN', mode
    for stub in stubs: stub.assert_no_pending_responses()
