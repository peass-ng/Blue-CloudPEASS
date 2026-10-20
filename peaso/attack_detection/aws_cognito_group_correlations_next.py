"""Link Cognito role-bearing group changes and subsequent membership grants."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def correlate_aws_cognito_role_group_membership(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = []
    for record in records:
        name = record.get('eventName')
        if record.get('eventSource') != 'cognito-idp.amazonaws.com' or name not in {'CreateGroup', 'UpdateGroup', 'AdminAddUserToGroup'}:
            continue
        if (record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
                or record.get('managementEvent') is not True or record.get('readOnly') is not False
                or record.get('errorCode') or record.get('errorMessage')):
            continue
        response = record.get('responseElements')
        if isinstance(response, Mapping) and (response.get('errorCode') or response.get('errorMessage')):
            continue
        when = _when(record.get('eventTime'))
        request = record.get('requestParameters')
        identity = record.get('userIdentity')
        account = record.get('recipientAccountId')
        region = record.get('awsRegion')
        if (when is None or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
                or not isinstance(identity.get('arn'), str) or not isinstance(account, str)
                or len(account) != 12 or not account.isdigit() or identity.get('accountId') != account
                or not isinstance(region, str) or not region
                or not isinstance(request.get('userPoolId'), str) or not request['userPoolId']
                or not isinstance(request.get('groupName'), str) or not request['groupName']):
            continue
        ordered.append((when, 1 if name == 'AdminAddUserToGroup' else 0, account, region,
                        request['userPoolId'], request['groupName'], record))
    ordered.sort(key=lambda item: item[:6])
    configured: dict[tuple[str, str, str, str], tuple[datetime, Mapping[str, Any]]] = {}
    matches = []
    for when, _, account, region, pool, group, record in ordered:
        key = (account, region, pool, group)
        if record['eventName'] in {'CreateGroup', 'UpdateGroup'}:
            role = record['requestParameters'].get('roleArn')
            if isinstance(role, str) and role.startswith(f'arn:aws:iam::{account}:role/'):
                configured[key] = (when, record)
            continue
        previous = configured.get(key)
        if previous is None or when - previous[0] > timedelta(minutes=30):
            continue
        group_event = previous[1]
        matches.append({
            'cloud.provider': 'aws', 'event.source': 'cognito-idp.amazonaws.com',
            'event.name': 'AdminAddUserToGroup', 'event.outcome': 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': record['userIdentity']['arn'],
            'target.id': pool + '/' + group,
            'request.cognito_user_added_to_role_group': True,
            'correlation_evidence': {'group_event_id': group_event.get('eventID'),
                                     'group_role_arn': group_event['requestParameters']['roleArn']},
        })
    return matches
