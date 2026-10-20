"""SQS control changes and resource-tag authorization correlation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import json
import re
from typing import Any


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def _queue_arn(url: Any, region: str, account: str) -> str | None:
    if not isinstance(url, str):
        return None
    match = re.fullmatch(
        rf'https://sqs\.{re.escape(region)}\.amazonaws\.com/{account}/([A-Za-z0-9_-]{{1,80}}(?:\.fifo)?)', url)
    return f'arn:aws:sqs:{region}:{account}:{match.group(1)}' if match else None


def _valid(record: Mapping[str, Any], source: str, names: set[str]) -> bool:
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    return (record.get('eventSource') == source and record.get('eventName') in names
            and record.get('eventCategory') == 'Management'
            and record.get('eventType') == 'AwsApiCall'
            and record.get('managementEvent') is True
            and record.get('readOnly') is False
            and not record.get('errorCode') and not record.get('errorMessage')
            and isinstance(account, str) and re.fullmatch(r'\d{12}', account) is not None
            and isinstance(region, str)
            and isinstance(record.get('requestParameters'), Mapping))


def normalize_aws_sqs_followup(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if not _valid(record, 'sqs.amazonaws.com', {'SetQueueAttributes'}):
        return None
    request = record['requestParameters']
    arn = _queue_arn(request.get('queueUrl'), record['awsRegion'], record['recipientAccountId'])
    if arn is None:
        return None
    attrs = request.get('attributes')
    attrs = attrs if isinstance(attrs, Mapping) else {}
    timeout = attrs.get('VisibilityTimeout')
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'sqs.amazonaws.com',
        'event.name': 'SetQueueAttributes', 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': record['recipientAccountId'], 'actor.id': identity.get('arn'),
        'target.id': arn,
        'request.sqs_managed_sse_disabled': attrs.get('SqsManagedSseEnabled') == 'false',
        'request.sqs_visibility_timeout_12h': timeout == '43200',
    }


def _policy_grants_tagged_receive(value: Any, queue_arn: str, key: str, tag: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        document = json.loads(value)
    except (ValueError, TypeError):
        return False
    statements = document.get('Statement') if isinstance(document, Mapping) else None
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get('Effect') != 'Allow':
            continue
        actions = statement.get('Action')
        resources = statement.get('Resource')
        action_ok = (actions in ('sqs:ReceiveMessage', 'sqs:*', '*')
                     or isinstance(actions, list) and any(x in actions for x in ('sqs:ReceiveMessage', 'sqs:*', '*')))
        resource_ok = resources == queue_arn or isinstance(resources, list) and queue_arn in resources
        condition = statement.get('Condition')
        equals = condition.get('StringEquals') if isinstance(condition, Mapping) else None
        expected = equals.get('aws:ResourceTag/' + key) if isinstance(equals, Mapping) else None
        if action_ok and resource_ok and expected == tag:
            return True
    return False


def correlate_aws_sqs_tagged_receive(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    events = []
    for record in records:
        if (_valid(record, 'iam.amazonaws.com', {'PutRolePolicy'})
                or _valid(record, 'sqs.amazonaws.com', {'TagQueue'})):
            when = _when(record.get('eventTime'))
            if when is not None:
                events.append((when, 0 if record['eventName'] == 'PutRolePolicy' else 1, record))
    events.sort(key=lambda item: item[:2])
    policies: list[tuple[datetime, str, str, Mapping[str, Any]]] = []
    results = []
    for when, _, event in events:
        request = event['requestParameters']
        account, region = event['recipientAccountId'], event['awsRegion']
        if event['eventName'] == 'PutRolePolicy':
            role, policy = request.get('roleName'), request.get('policyDocument')
            if (isinstance(role, str) and role and isinstance(policy, str)
                    and isinstance(request.get('policyName'), str)):
                policies.append((when, account, policy, event))
            continue
        queue_arn = _queue_arn(request.get('queueUrl'), region, account)
        tags = request.get('tags')
        if queue_arn is None or not isinstance(tags, Mapping):
            continue
        for prior_when, prior_account, policy, prior_event in policies:
            if prior_account != account or when < prior_when or when - prior_when > timedelta(hours=24):
                continue
            matching = [key for key, value in tags.items()
                        if isinstance(key, str) and isinstance(value, str)
                        and _policy_grants_tagged_receive(policy, queue_arn, key, value)]
            if not matching:
                continue
            identity = event.get('userIdentity')
            identity = identity if isinstance(identity, Mapping) else {}
            results.append({
                'cloud.provider': 'aws', 'event.source': 'sqs.amazonaws.com',
                'event.name': 'TagQueue', 'event.outcome': 'success',
                'event.id': event.get('eventID'), 'event.time': event.get('eventTime'),
                'account.id': account, 'actor.id': identity.get('arn'), 'target.id': queue_arn,
                'request.sqs_tag_activated_receive_grant': True,
                'correlation_evidence': {'iam_policy_event_id': prior_event.get('eventID'),
                                         'tag_keys': sorted(matching)},
            })
            break
    return results
