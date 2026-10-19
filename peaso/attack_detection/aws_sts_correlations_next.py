"""Correlate a successful STS A -> B -> A role-session cycle."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except ValueError:
        return None


def correlate_aws_sts_role_cycle(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    calls = []
    for record in records:
        if (record.get('eventSource') != 'sts.amazonaws.com' or record.get('eventName') != 'AssumeRole'
                or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
                or record.get('managementEvent') is not True or record.get('readOnly') is not True
                or record.get('errorCode') or record.get('errorMessage')):
            continue
        when = _time(record.get('eventTime'))
        account, region = record.get('recipientAccountId'), record.get('awsRegion')
        request, identity, response = (record.get(key) for key in ('requestParameters', 'userIdentity', 'responseElements'))
        if (when is None or not isinstance(account, str) or len(account) != 12 or not account.isdigit()
                or not isinstance(region, str) or not region or not isinstance(request, Mapping)
                or not isinstance(identity, Mapping) or identity.get('type') != 'AssumedRole'
                or identity.get('accountId') != account or not isinstance(response, Mapping)
                or response.get('errorCode') or response.get('errorMessage')):
            continue
        session = identity.get('sessionContext')
        issuer = session.get('sessionIssuer') if isinstance(session, Mapping) else None
        user = response.get('assumedRoleUser')
        source, target = issuer.get('arn') if isinstance(issuer, Mapping) else None, request.get('roleArn')
        output_arn = user.get('arn') if isinstance(user, Mapping) else None
        if (not isinstance(issuer, Mapping) or issuer.get('type') != 'Role'
                or issuer.get('accountId') != account or not isinstance(user, Mapping)
                or not isinstance(source, str) or not isinstance(target, str)
                or not isinstance(output_arn, str) or not isinstance(identity.get('arn'), str)
                or not source.startswith(f'arn:aws:iam::{account}:role/')
                or not target.startswith(f'arn:aws:iam::{account}:role/')
                or source == target
                or not output_arn.startswith(f'arn:aws:sts::{account}:assumed-role/{target.rsplit("/", 1)[-1]}/')
                or not identity['arn'].startswith(f'arn:aws:sts::{account}:assumed-role/{source.rsplit("/", 1)[-1]}/')
                or not isinstance(record.get('eventID'), str)):
            continue
        calls.append((when, account, region, source, target, identity['arn'], output_arn, record))
    calls.sort(key=lambda item: item[0])
    findings = []
    for earlier in calls:
        for later in calls:
            if (earlier is later or earlier[1:3] != later[1:3]
                    or earlier[3] != later[4] or earlier[4] != later[3]
                    or earlier[6] != later[5]
                    or not timedelta(0) <= later[0] - earlier[0] <= timedelta(minutes=30)):
                continue
            record = later[7]
            findings.append({
                'cloud.provider': 'aws', 'event.source': 'sts.amazonaws.com',
                'event.name': 'AssumeRole', 'event.outcome': 'success',
                'event.id': record['eventID'], 'event.time': record['eventTime'],
                'account.id': later[1], 'actor.id': later[5], 'target.id': later[4],
                'request.sts_role_cycle': True,
                'correlation_evidence': {'first_event_id': earlier[7]['eventID'],
                                         'first_role_arn': earlier[3], 'intermediate_role_arn': earlier[4]},
            })
    return findings
