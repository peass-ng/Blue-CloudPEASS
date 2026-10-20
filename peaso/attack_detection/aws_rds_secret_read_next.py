"""Reads of RDS managed master credentials from Secrets Manager CloudTrail."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_ARN = re.compile(r'^arn:aws(?:-us-gov|-cn)?:secretsmanager:([a-z0-9-]+):(\d{12}):secret:(rds!db-[0-9a-f-]{36}-[A-Za-z0-9]{6})$')
_NAME = re.compile(r'^rds!db-[0-9a-f-]{36}(?:-[A-Za-z0-9]{6})?$')


def normalize_aws_rds_managed_secret_read(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource') != 'secretsmanager.amazonaws.com'
            or record.get('eventName') != 'GetSecretValue'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('eventCategory') != 'Management'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not True
            or record.get('errorCode') or record.get('errorMessage')):
        return None
    req = record.get('requestParameters');identity = record.get('userIdentity')
    account = record.get('recipientAccountId');region = record.get('awsRegion')
    if (not isinstance(req, Mapping) or not isinstance(identity, Mapping)
            or identity.get('type') not in {'IAMUser', 'AssumedRole', 'Root'}
            or not isinstance(identity.get('arn'), str)
            or not isinstance(account, str) or re.fullmatch(r'\d{12}', account) is None):
        return None
    secret = req.get('secretId')
    if not isinstance(secret, str):
        return None
    match = _ARN.fullmatch(secret)
    if match:
        if match.group(1) != region or match.group(2) != account:
            return None
    elif _NAME.fullmatch(secret) is None:
        return None
    return {
        'cloud.provider': 'aws', 'event.source': 'secretsmanager.amazonaws.com',
        'event.name': 'GetSecretValue', 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity['arn'], 'target.id': secret,
        'request.rds_managed_master_secret_read': True,
    }


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except ValueError:
        return None


def correlate_aws_rds_proxy_auth_secret_read(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Link a recently configured proxy auth secret to its later IAM reader."""
    rows = list(records)
    configured = []
    for record in rows:
        if (record.get('eventSource') != 'rds.amazonaws.com'
                or record.get('eventName') != 'CreateDBProxy'
                or record.get('eventType') != 'AwsApiCall'
                or record.get('eventCategory') != 'Management'
                or record.get('managementEvent') is not True
                or record.get('readOnly') is not False
                or record.get('errorCode') or record.get('errorMessage')
                or not isinstance(record.get('requestParameters'), Mapping)
                or not isinstance(record.get('recipientAccountId'), str)
                or _time(record.get('eventTime')) is None):
            continue
        req = record['requestParameters']
        if not isinstance(req.get('dBProxyName'), str) or not req['dBProxyName']:
            continue
        auth = req.get('auth')
        if not isinstance(auth, list):
            continue
        for entry in auth:
            if isinstance(entry, Mapping) and isinstance(entry.get('secretArn'), str):
                configured.append((record, entry['secretArn']))
    out = []
    for record in rows:
        if (record.get('eventSource') != 'secretsmanager.amazonaws.com'
                or record.get('eventName') != 'GetSecretValue'
                or record.get('eventType') != 'AwsApiCall'
                or record.get('eventCategory') != 'Management'
                or record.get('managementEvent') is not True
                or record.get('readOnly') is not True
                or record.get('errorCode') or record.get('errorMessage')
                or not isinstance(record.get('requestParameters'), Mapping)
                or not isinstance(record.get('userIdentity'), Mapping)
                or record['userIdentity'].get('type') not in {'IAMUser', 'AssumedRole', 'Root'}
                or not isinstance(record['userIdentity'].get('arn'), str)
                or _time(record.get('eventTime')) is None):
            continue
        secret = record['requestParameters'].get('secretId')
        prior = next((p for p, arn in configured if arn == secret
                      and p['recipientAccountId'] == record.get('recipientAccountId')
                      and timedelta(0) <= _time(record['eventTime']) - _time(p['eventTime']) <= timedelta(hours=24)), None)
        if not prior:
            continue
        out.append({
            'cloud.provider': 'aws', 'event.source': 'secretsmanager.amazonaws.com',
            'event.name': 'GetSecretValue', 'event.outcome': 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': record.get('recipientAccountId'),
            'actor.id': record['userIdentity']['arn'], 'target.id': secret,
            'request.rds_proxy_auth_secret_read_after_configuration': True,
            'correlation_evidence': {'proxy_configuration_event_id': prior.get('eventID'),
                                     'proxy_name': prior['requestParameters']['dBProxyName']},
        })
    return out
