"""Pure helper transcription of Prowler iam:PassRole to Bedrock AgentCore (iam_policy_passrole_to_bedrock_agentcore_restricted).

Generated mechanically (ast) from prowler/providers/aws/services/iam/iam_policy_passrole_to_bedrock_agentcore_restricted/iam_policy_passrole_to_bedrock_agentcore_restricted.py at
revision 61d2cc55c4539a6b48a3cf9f3729d8f2af300882 (Apache-2.0); docstrings and comments are dropped, logic is unchanged.
Source sha256: 1daf515181121a853c6004bc2dd5744fe407bdd3222328a5d0b554c0d4dd8cc5. Inputs are private copies of collected policy documents.
"""
import re  # noqa: F401

from .claude_aws_a_common import iam_pattern_matches  # noqa: F401


AGENTCORE_SERVICE_PREFIX = 'bedrock-agentcore'


AGENTCORE_SERVICE_PRINCIPAL = 'bedrock-agentcore.amazonaws.com'


AGENTCORE_PRINCIPAL_FAMILY_PATTERN = re.compile(f'^([a-z0-9-]+\\.)?{AGENTCORE_SERVICE_PREFIX}(-[a-z0-9-]+)?\\.amazonaws\\.com$', re.IGNORECASE)


AGENTCORE_PRINCIPAL_PROBES = (AGENTCORE_SERVICE_PRINCIPAL, f'runtime-identity.{AGENTCORE_SERVICE_PRINCIPAL}')


_SHORTEST_ROLE_NAME = 'role/a'


_LONGEST_ROLE_NAME = 'role/' + 'r0le-name-' * 6 + 'abcd'


EVERY_ROLE_RESOURCE_PROBES = (_SHORTEST_ROLE_NAME, _LONGEST_ROLE_NAME)


_PASSED_TO_SERVICE_OPERATORS = frozenset((f'{qualifier}{operator}{suffix}'.lower() for qualifier in ('', 'ForAnyValue:', 'ForAllValues:') for operator in ('StringEquals', 'StringEqualsIgnoreCase', 'StringLike') for suffix in ('', 'IfExists')))


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statements(document: dict) -> list:
    statements = document.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _covers_passrole(statement: dict) -> bool:
    for action in _as_list(statement.get('Action')):
        if not isinstance(action, str):
            continue
        service, separator, operation = action.strip().partition(':')
        if separator != ':' or (service == '*' and operation == '*'):
            continue
        if not iam_pattern_matches(service, 'iam'):
            continue
        if iam_pattern_matches(operation, 'PassRole'):
            return True
    return False


def _grants_agentcore_action(document: dict) -> bool:
    for statement in _statements(document):
        if statement.get('Effect') != 'Allow':
            continue
        for action in _as_list(statement.get('Action')):
            if not isinstance(action, str):
                continue
            service, separator, _ = action.strip().partition(':')
            if separator == ':' and iam_pattern_matches(service, AGENTCORE_SERVICE_PREFIX):
                return True
    return False


def _passed_to_service_values(statement: dict) -> list:
    values = []
    condition = statement.get('Condition', {})
    if not isinstance(condition, dict):
        return values
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        lowered_operator = operator.lower()
        if lowered_operator not in _PASSED_TO_SERVICE_OPERATORS:
            continue
        for key, value in block.items():
            if isinstance(key, str) and key.lower() == 'iam:passedtoservice':
                values.extend(_as_list(value))
    return values


def _null_guarded_keys(condition: dict) -> set:
    guarded = set()
    for operator, block in condition.items():
        if not isinstance(operator, str) or operator.lower() != 'null':
            continue
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if not isinstance(key, str):
                continue
            candidates = value if isinstance(value, list) else [value]
            if candidates and all((isinstance(candidate, (str, bool)) and str(candidate).strip().lower() == 'false' for candidate in candidates)):
                guarded.add(key.lower())
    return guarded


def _passed_to_service_pin_is_defeasible(statement: dict) -> bool:
    defeasible = []
    condition = statement.get('Condition', {})
    if not isinstance(condition, dict):
        return False
    guarded = 'iam:passedtoservice' in _null_guarded_keys(condition)
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        lowered_operator = operator.lower()
        if lowered_operator not in _PASSED_TO_SERVICE_OPERATORS:
            continue
        if not any((isinstance(key, str) and key.lower() == 'iam:passedtoservice' for key in block)):
            continue
        defeasible.append((lowered_operator.endswith('ifexists') or lowered_operator.startswith('forallvalues:')) and (not guarded))
    return bool(defeasible) and all(defeasible)


def _names_agentcore(values: list) -> bool:
    return any((isinstance(value, str) and (AGENTCORE_PRINCIPAL_FAMILY_PATTERN.match(value.strip()) or any((iam_pattern_matches(value, probe) for probe in AGENTCORE_PRINCIPAL_PROBES))) for value in values))


def _targets_agentcore(statement: dict, document: dict) -> bool:
    values = _passed_to_service_values(statement)
    if _names_agentcore(values):
        return True
    if values and (not _passed_to_service_pin_is_defeasible(statement)):
        return False
    return _grants_agentcore_action(document)


def _names_every_role(resource: str) -> bool:
    candidate = resource.strip()
    if candidate == '*':
        return True
    arn_fields = candidate.split(':', 5)
    if len(arn_fields) < 6:
        if '*' not in arn_fields[-1]:
            return False
        if not iam_pattern_matches(arn_fields[0], 'arn'):
            return False
        if len(arn_fields) > 2 and (not iam_pattern_matches(arn_fields[2], 'iam')):
            return False
        if len(arn_fields) == 4:
            region_head = arn_fields[3].split('*', 1)[0].replace('?', '')
            if region_head:
                return False
        if len(arn_fields) == 5:
            account_head = arn_fields[4].split('*', 1)[0].replace('?', '')
            if account_head and (not account_head.isdigit()):
                return False
        return True
    if not iam_pattern_matches(arn_fields[0], 'arn'):
        return False
    if not iam_pattern_matches(arn_fields[2], 'iam'):
        return False
    if not iam_pattern_matches(arn_fields[3], ''):
        return False
    account_field = arn_fields[4]
    account_head = account_field.split('*', 1)[0].replace('?', '')
    if account_head and (not account_head.isdigit()):
        return False
    if '*' not in account_field and len(account_field) != 12:
        return False
    return all((iam_pattern_matches(arn_fields[5], probe) for probe in EVERY_ROLE_RESOURCE_PROBES))


def _allows_any_role(statement: dict) -> bool:
    resources = _as_list(statement.get('Resource'))
    if not resources:
        return 'NotResource' in statement
    return any((isinstance(resource, str) and _names_every_role(resource) for resource in resources))


def _deny_removes_passrole(statement: dict) -> bool:
    for action in _as_list(statement.get('Action')):
        if not isinstance(action, str):
            continue
        service, separator, operation = action.strip().partition(':')
        if separator != ':':
            if service == '*':
                return True
            continue
        if not iam_pattern_matches(service, 'iam'):
            continue
        if iam_pattern_matches(operation, 'PassRole'):
            return True
    return False


def _denies_passrole_everywhere(document: dict) -> bool:
    for statement in _statements(document):
        if statement.get('Effect') != 'Deny' or statement.get('Condition'):
            continue
        if not _deny_removes_passrole(statement):
            continue
        if any((isinstance(resource, str) and resource.strip() == '*' for resource in _as_list(statement.get('Resource')))):
            return True
    return False


def _has_unevaluated_notaction(document: dict) -> bool:
    for statement in _statements(document):
        if statement.get('Effect') == 'Allow' and 'NotAction' in statement:
            return True
    return False
