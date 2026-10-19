"""Correlate EMR Serverless session creation and endpoint reads by another actor."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
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


def _actor(identity: Any, account: str) -> str | None:
    if not isinstance(identity, Mapping) or identity.get('accountId') != account:
        return None
    if identity.get('type') == 'AssumedRole':
        context = identity.get('sessionContext')
        issuer = context.get('sessionIssuer') if isinstance(context, Mapping) else None
        arn = issuer.get('arn') if isinstance(issuer, Mapping) else None
        return arn if isinstance(arn, str) and arn.startswith(f'arn:aws:iam::{account}:role/') else None
    arn = identity.get('arn')
    return arn if identity.get('type') in {'IAMUser', 'Root'} and isinstance(arn, str) else None


def correlate_aws_emr_session_endpoint_cross_actor(
    records: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    events = []
    for record in records:
        name = record.get('eventName')
        if (record.get('eventSource') != 'emr-serverless.amazonaws.com'
                or name not in {'StartSession', 'GetSessionEndpoint'}
                or record.get('eventCategory') != 'Management'
                or record.get('eventType') != 'AwsApiCall'
                or record.get('managementEvent') is not True
                or record.get('readOnly') is not (name == 'GetSessionEndpoint')
                or record.get('errorCode') or record.get('errorMessage')):
            continue
        account, region = record.get('recipientAccountId'), record.get('awsRegion')
        request, when = record.get('requestParameters'), _when(record.get('eventTime'))
        if (not isinstance(account, str) or not re.fullmatch(r'\d{12}', account)
                or not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region)
                or not isinstance(request, Mapping) or when is None):
            continue
        app = request.get('applicationId')
        if not isinstance(app, str) or not re.fullmatch(r'[0-9a-z]+', app):
            continue
        actor = _actor(record.get('userIdentity'), account)
        if actor is None:
            continue
        events.append((when, 0 if name == 'StartSession' else 1,
                       account, region, app, actor, record))
    events.sort(key=lambda x: x[:5])
    creators: dict[tuple[str, str, str, str], tuple[datetime, str, Mapping[str, Any]]] = {}
    matches = []
    for when, _, account, region, app, actor, event in events:
        request, response = event['requestParameters'], event.get('responseElements')
        if event['eventName'] == 'StartSession':
            if not isinstance(response, Mapping):
                continue
            session = response.get('sessionId')
            if (not isinstance(session, str) or not re.fullmatch(r'[0-9a-z]+', session)
                    or response.get('applicationId') != app
                    or response.get('arn') != f'arn:aws:emr-serverless:{region}:{account}:/applications/{app}/sessions/{session}'):
                continue
            creators[(account, region, app, session)] = (when, actor, event)
            continue
        session = request.get('sessionId')
        if not isinstance(session, str) or not re.fullmatch(r'[0-9a-z]+', session):
            continue
        prior = creators.get((account, region, app, session))
        if prior is None or not timedelta(0) <= when - prior[0] <= timedelta(hours=24) or prior[1] == actor:
            continue
        matches.append({'cloud.provider': 'aws', 'event.source': 'emr-serverless.amazonaws.com',
                        'event.name': 'GetSessionEndpoint', 'event.outcome': 'success',
                        'event.id': event.get('eventID'), 'event.time': event.get('eventTime'),
                        'account.id': account, 'actor.id': actor,
                        'target.id': f'arn:aws:emr-serverless:{region}:{account}:/applications/{app}/sessions/{session}',
                        'request.emr_session_endpoint_cross_actor': True,
                        'correlation_evidence': {'start_session_event_id': prior[2].get('eventID'),
                                                 'session_creator': prior[1]}})
    return matches
