"""Pure helper transcription of Prowler AgentCore workload access token wildcard (iam_policy_no_agentcore_workload_access_token_wildcard).

Generated mechanically (ast) from prowler/providers/aws/services/iam/iam_policy_no_agentcore_workload_access_token_wildcard/iam_policy_no_agentcore_workload_access_token_wildcard.py at
revision 61d2cc55c4539a6b48a3cf9f3729d8f2af300882 (Apache-2.0); docstrings and comments are dropped, logic is unchanged.
Source sha256: 9b0680615e8e0bc19b3627fe78e39e3fe57922c2f3ca592a35be58321053219e. Inputs are private copies of collected policy documents.
"""
import re  # noqa: F401

from .claude_aws_a_common import iam_pattern_matches  # noqa: F401


AGENTCORE_SERVICE_PREFIX = 'bedrock-agentcore'


WORKLOAD_ACCESS_TOKEN_OPERATIONS = ('GetWorkloadAccessToken', 'GetWorkloadAccessTokenForJWT', 'GetWorkloadAccessTokenForUserId')


WORKLOAD_IDENTITY_SEGMENT = 'workload-identity-directory'


NON_WORKLOAD_IDENTITY_SEGMENTS = ('ab-test', 'batch-evaluate', 'browser', 'browser-custom', 'browser-profile', 'capacity-provider', 'code-interpreter', 'code-interpreter-custom', 'configuration-bundle', 'dataset', 'evaluator', 'gateway', 'harness', 'memory', 'online-evaluation-config', 'payment-manager', 'policy-engine', 'recommendation', 'registry', 'runtime', 'token-vault', 'tool')


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statements(document: dict) -> list:
    statements = document.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _covered_token_operations(statement: dict) -> set:
    covered = set()
    for action in _as_list(statement.get('Action')):
        if not isinstance(action, str):
            continue
        service, separator, operation = action.strip().partition(':')
        if separator != ':' or (service == '*' and operation == '*'):
            continue
        if not iam_pattern_matches(service, AGENTCORE_SERVICE_PREFIX):
            continue
        covered.update((token_operation for token_operation in WORKLOAD_ACCESS_TOKEN_OPERATIONS if iam_pattern_matches(operation, token_operation)))
    return covered


def _token_operations_removed_by(statement: dict) -> set:
    removed = set()
    for action in _as_list(statement.get('Action')):
        if not isinstance(action, str):
            continue
        service, separator, operation = action.strip().partition(':')
        if separator != ':':
            if service == '*':
                removed.update(WORKLOAD_ACCESS_TOKEN_OPERATIONS)
            continue
        if not iam_pattern_matches(service, AGENTCORE_SERVICE_PREFIX):
            continue
        removed.update((token_operation for token_operation in WORKLOAD_ACCESS_TOKEN_OPERATIONS if iam_pattern_matches(operation, token_operation)))
    return removed


def _may_reach_segment(resource_field: str, segment: str) -> bool:
    head, spans = (resource_field.split('*', 1)[0], '*' in resource_field)
    for index in range(min(len(head), len(segment))):
        if head[index] != '?' and head[index] != segment[index]:
            return False
    if len(head) >= len(segment):
        return True
    return spans


def _reaches_other_workload_identities(resource: str) -> bool:
    resource = resource.strip()
    if resource == '*':
        return True
    arn_fields = resource.split(':', 5)
    if len(arn_fields) < 6:
        if '*' not in arn_fields[-1]:
            return False
        if not iam_pattern_matches(arn_fields[0], 'arn'):
            return False
        return len(arn_fields) < 3 or iam_pattern_matches(arn_fields[2], AGENTCORE_SERVICE_PREFIX)
    if not iam_pattern_matches(arn_fields[0], 'arn'):
        return False
    if not iam_pattern_matches(arn_fields[2], AGENTCORE_SERVICE_PREFIX):
        return False
    resource_field = arn_fields[5]
    if not any((_may_reach_segment(resource_field, segment) for segment in NON_WORKLOAD_IDENTITY_SEGMENTS)):
        return False
    return _may_reach_segment(resource_field, WORKLOAD_IDENTITY_SEGMENT)


def _is_workload_identity_scoped(statement: dict) -> bool:
    resources = _as_list(statement.get('Resource'))
    if not resources:
        return 'NotResource' not in statement
    return not any((isinstance(resource, str) and _reaches_other_workload_identities(resource) for resource in resources))


def _denied_token_operations(document: dict) -> set:
    denied = set()
    for statement in _statements(document):
        if statement.get('Effect') != 'Deny' or statement.get('Condition'):
            continue
        if any((isinstance(resource, str) and resource.strip() == '*' for resource in _as_list(statement.get('Resource')))):
            denied.update(_token_operations_removed_by(statement))
    return denied


def _has_unevaluated_notaction(document: dict) -> bool:
    for statement in _statements(document):
        if statement.get('Effect') == 'Allow' and 'NotAction' in statement:
            return True
    return False
