"""Lambda role assignment and bounded creation-to-access correlations."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import json
import re
from typing import Any


_EVENTS = {
    'CreateFunction20150331', 'UpdateFunctionConfiguration20150331v2',
    'UpdateFunctionCode20150331v2', 'AddPermission20150331v2',
    'CreateEventSourceMapping20150331',
}


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except ValueError:
        return None


def _function(record: Mapping[str, Any]) -> str | None:
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    request = record.get('requestParameters')
    if (not isinstance(account, str) or re.fullmatch(r'\d{12}', account) is None
            or not isinstance(region, str) or not isinstance(request, Mapping)):
        return None
    name = request.get('functionName')
    if not isinstance(name, str):
        return None
    if re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name):
        return f'arn:aws:lambda:{region}:{account}:function:{name}'
    if re.fullmatch(rf'arn:aws:lambda:{re.escape(region)}:{account}:function:[A-Za-z0-9_-]{{1,64}}', name):
        return name
    return None


def _valid(record: Mapping[str, Any]) -> bool:
    return (record.get('eventSource') == 'lambda.amazonaws.com'
            and record.get('eventName') in _EVENTS
            and record.get('eventCategory') == 'Management'
            and record.get('eventType') == 'AwsApiCall'
            and record.get('managementEvent') is True
            and record.get('readOnly') is False
            and not record.get('errorCode') and not record.get('errorMessage')
            and _function(record) is not None)


def _role_assigned(record: Mapping[str, Any]) -> bool:
    request, response = record.get('requestParameters'), record.get('responseElements')
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return False
    account, role = record['recipientAccountId'], request.get('role')
    return (isinstance(role, str)
            and re.fullmatch(rf'arn:aws:iam::{account}:role/[A-Za-z0-9_+=,.@\-/]+', role) is not None
            and response.get('role') == role
            and response.get('functionArn') == _function(record))


def normalize_aws_lambda_role_assignment(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (not _valid(record)
            or record.get('eventName') != 'UpdateFunctionConfiguration20150331v2'
            or not _role_assigned(record)):
        return None
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'lambda.amazonaws.com',
        'event.name': record['eventName'], 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': record['recipientAccountId'], 'actor.id': identity.get('arn'),
        'target.id': _function(record),
        'request.lambda_execution_role_assigned': True,
    }


def _grant(record: Mapping[str, Any]) -> bool:
    request, response = record.get('requestParameters'), record.get('responseElements')
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return False
    principal = request.get('principal')
    if (not isinstance(principal, str)
            or not re.fullmatch(r'arn:aws:iam::\d{12}:role/[A-Za-z0-9_+=,.@\-/]+', principal)
            or request.get('action') != 'lambda:InvokeFunction'):
        return False
    raw = response.get('statement')
    if not isinstance(raw, str):
        return False
    try:
        statement = json.loads(raw)
    except ValueError:
        return False
    return (isinstance(statement, Mapping) and statement.get('Effect') == 'Allow'
            and statement.get('Sid') == request.get('statementId')
            and statement.get('Action') == 'lambda:InvokeFunction'
            and statement.get('Principal') == {'AWS': principal}
            and statement.get('Resource') == _function(record))


def _mapped_sqs(record: Mapping[str, Any]) -> bool:
    request, response = record.get('requestParameters'), record.get('responseElements')
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return False
    account, region = record['recipientAccountId'], record['awsRegion']
    source = request.get('eventSourceArn')
    return (request.get('enabled') is True and isinstance(source, str)
            and re.fullmatch(rf'arn:aws:sqs:{re.escape(region)}:{account}:[A-Za-z0-9_-]{{1,80}}(?:\.fifo)?', source) is not None
            and response.get('eventSourceArn') == source
            and response.get('functionArn') == _function(record)
            and isinstance(response.get('uUID'), str))


def correlate_aws_lambda_privesc(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = []
    for record in records:
        if not _valid(record):
            continue
        when = _time(record.get('eventTime'))
        identity = record.get('userIdentity')
        actor = identity.get('arn') if isinstance(identity, Mapping) else None
        if when is None or not isinstance(actor, str):
            continue
        name = record['eventName']
        response = record.get('responseElements')
        if name in {'CreateFunction20150331', 'UpdateFunctionConfiguration20150331v2'}:
            if not _role_assigned(record):
                continue
        elif name == 'UpdateFunctionCode20150331v2':
            if not isinstance(response, Mapping) or response.get('functionArn') != _function(record):
                continue
        elif name == 'AddPermission20150331v2':
            if not _grant(record):
                continue
        elif name == 'CreateEventSourceMapping20150331' and not _mapped_sqs(record):
            continue
        ordered.append((when, record['recipientAccountId'], _function(record), actor, name, record))
    ordered.sort(key=lambda value: value[0])
    prior: dict[tuple[str, str, str], list[tuple]] = {}
    matches = []
    for current in ordered:
        when, account, function, actor, name, event = current
        key = (account, function, actor)
        evidence = [old for old in prior.get(key, []) if when - old[0] <= timedelta(minutes=10)]
        field, parent = None, None
        if name == 'UpdateFunctionCode20150331v2':
            parent = next((old for old in reversed(evidence) if old[4] == 'UpdateFunctionConfiguration20150331v2'), None)
            field = 'request.lambda_role_assignment_followed_by_code_update'
        elif name == 'AddPermission20150331v2':
            parent = next((old for old in reversed(evidence) if old[4] == 'CreateFunction20150331'), None)
            field = 'request.lambda_new_function_invoke_grant'
        elif name == 'CreateEventSourceMapping20150331':
            parent = next((old for old in reversed(evidence) if old[4] == 'CreateFunction20150331'), None)
            field = 'request.lambda_new_function_sqs_mapping'
        if field and parent:
            matches.append({
                'cloud.provider': 'aws', 'event.source': 'lambda.amazonaws.com',
                'event.name': name, 'event.outcome': 'success',
                'event.id': event.get('eventID'), 'event.time': event.get('eventTime'),
                'account.id': account, 'actor.id': actor, 'target.id': function,
                field: True,
                'correlation_evidence': {'earlier_event_id': parent[5].get('eventID')},
            })
        prior.setdefault(key, []).append(current)
    return matches
