"""Pure helper transcription of Prowler service-principal trust source binding (iam_role_service_trust_restricts_source_to_account).

Generated mechanically (ast) from prowler/providers/aws/services/iam/iam_role_service_trust_restricts_source_to_account/iam_role_service_trust_restricts_source_to_account.py at
revision 61d2cc55c4539a6b48a3cf9f3729d8f2af300882 (Apache-2.0); docstrings and comments are dropped, logic is unchanged.
Source sha256: c131a1a623570b2419f0406f4ce4ec5eac53a1a079ecb32f8b3903a0f5b9b871. Inputs are private copies of collected policy documents.
"""
import re  # noqa: F401

from .claude_aws_a_common import iam_pattern_matches  # noqa: F401


ASSUME_ROLE_ACTION = 'sts:AssumeRole'


ACCOUNT_ID_PATTERN = re.compile('^\\d{12}$')


ORGANIZATION_ID_PATTERN = re.compile('^o-[a-z0-9]{10,32}$')


ORGANIZATION_PATH_PATTERN = re.compile('^o-[a-z0-9]{10,32}/')


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _grants_assume_role(statement: dict) -> bool:
    for action in _as_list(statement.get('Action')):
        if not isinstance(action, str):
            continue
        if iam_pattern_matches(action, ASSUME_ROLE_ACTION):
            return True
    return False


def _trusts_service_principal(statement: dict) -> bool:
    principal = statement.get('Principal', {})
    if not isinstance(principal, dict):
        return principal == '*'
    return any((isinstance(service, str) and service for service in _as_list(principal.get('Service'))))


_COMPARING_CONDITION_OPERATORS = frozenset((f'{qualifier}{operator}{suffix}'.lower() for qualifier in ('', 'ForAnyValue:', 'ForAllValues:') for suffix in ('', 'IfExists') for operator in ('StringEquals', 'StringEqualsIgnoreCase', 'StringLike', 'ArnEquals', 'ArnLike')))


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
            if candidates and all((isinstance(candidate, str) and candidate.strip().lower() == 'false' for candidate in candidates)):
                guarded.add(key.lower())
    return guarded


def _enforced_condition_value_groups(statement: dict, condition_key: str) -> list:
    groups = []
    condition = statement.get('Condition', {})
    if not isinstance(condition, dict):
        return groups
    null_guarded = _null_guarded_keys(condition)
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        lowered_operator = operator.lower()
        if lowered_operator not in _COMPARING_CONDITION_OPERATORS:
            continue
        group = []
        for key, value in block.items():
            if not isinstance(key, str) or key.lower() != condition_key:
                continue
            if (lowered_operator.startswith('forallvalues:') or lowered_operator.endswith('ifexists')) and key.lower() not in null_guarded:
                continue
            group.extend(value if isinstance(value, list) else [value])
        if group:
            groups.append(group)
    return groups


def _pins_every_value(statement: dict, condition_key: str, qualifies) -> bool:
    return any((all((qualifies(value) for value in group)) for group in _enforced_condition_value_groups(statement, condition_key)))


def _is_account_id(value) -> bool:
    return isinstance(value, str) and bool(ACCOUNT_ID_PATTERN.match(value))


def _pins_source_account(statement: dict) -> bool:
    return _pins_every_value(statement, 'aws:sourceaccount', _is_account_id)


def _arn_carries_account(value) -> bool:
    if not isinstance(value, str):
        return False
    arn_fields = value.split(':')
    return len(arn_fields) >= 5 and _is_account_id(arn_fields[4])


def _pins_source_arn_to_account(statement: dict) -> bool:
    return _pins_every_value(statement, 'aws:sourcearn', _arn_carries_account)


def _pins_source_organization(statement: dict) -> bool:
    return _pins_every_value(statement, 'aws:sourceorgid', lambda value: isinstance(value, str) and bool(ORGANIZATION_ID_PATTERN.match(value))) or _pins_every_value(statement, 'aws:sourceorgpaths', lambda value: isinstance(value, str) and bool(ORGANIZATION_PATH_PATTERN.match(value)))


def _prevents_confused_deputy(statement: dict) -> bool:
    return _pins_source_account(statement) or _pins_source_arn_to_account(statement) or _pins_source_organization(statement)


def _has_enforced_condition(statement: dict) -> bool:
    condition = statement.get('Condition', {})
    if not isinstance(condition, dict):
        return False
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        lowered_operator = operator.lower()
        if 'not' in lowered_operator or lowered_operator.endswith('ifexists'):
            continue
        if any((isinstance(key, str) for key in block)):
            return True
    return False


def _is_plain_service_trust_policy(statements: list) -> bool:
    for statement in statements:
        if not isinstance(statement, dict):
            return False
        if statement.get('Effect') != 'Allow' or not _grants_assume_role(statement):
            return False
        principal = statement.get('Principal', {})
        if not isinstance(principal, dict) or set(principal.keys()) != {'Service'}:
            return False
    return True
