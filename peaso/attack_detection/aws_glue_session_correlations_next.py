"""Correlate Glue session creators with later statement callers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def correlate_aws_glue_cross_actor_statements(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = []
    for record in records:
        if record.get('eventSource') != 'glue.amazonaws.com' or record.get('eventName') not in {'CreateSession', 'RunStatement'}:
            continue
        if (record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
                or record.get('managementEvent') is not True or record.get('readOnly') is not False
                or record.get('errorCode') or record.get('errorMessage')):
            continue
        response = record.get('responseElements')
        if isinstance(response, Mapping) and (response.get('errorCode') or response.get('errorMessage')):
            continue
        when = _time(record.get('eventTime'))
        request = record.get('requestParameters')
        identity = record.get('userIdentity')
        account = record.get('recipientAccountId')
        region = record.get('awsRegion')
        if (when is None or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
                or not isinstance(identity.get('arn'), str) or not isinstance(account, str)
                or len(account) != 12 or not account.isdigit() or identity.get('accountId') != account
                or not isinstance(region, str) or not region):
            continue
        session = request.get('id') if record.get('eventName') == 'CreateSession' else request.get('sessionId')
        if not isinstance(session, str) or not session:
            continue
        ordered.append((when, 0 if record['eventName'] == 'CreateSession' else 1, account, region, session, record))
    ordered.sort(key=lambda item: item[:5])
    creators: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    matches = []
    for _, _, account, region, session, record in ordered:
        key = (account, region, session)
        if record['eventName'] == 'CreateSession':
            role = record['requestParameters'].get('role')
            if isinstance(role, str) and role.startswith(f'arn:aws:iam::{account}:role/'):
                creators[key] = record
            continue
        created = creators.get(key)
        if created is None:
            continue
        creator_arn = created['userIdentity']['arn']
        actor_arn = record['userIdentity']['arn']
        if actor_arn == creator_arn:
            continue
        matches.append({
            'cloud.provider': 'aws', 'event.source': 'glue.amazonaws.com',
            'event.name': 'RunStatement', 'event.outcome': 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor_arn, 'target.id': session,
            'request.glue_cross_actor_session_statement': True,
            'correlation_evidence': {'creator_event_id': created.get('eventID'),
                                     'creator_arn': creator_arn,
                                     'session_role_arn': created['requestParameters']['role']},
        })
    return matches
