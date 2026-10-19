"""RDS public clone, deletion-protection removal, stop and password reset."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_NAMES = {'RestoreDBInstanceFromDBSnapshot', 'ModifyDBInstance', 'StopDBInstance'}


def _valid(record: Mapping[str, Any]) -> bool:
    return (record.get('eventSource') == 'rds.amazonaws.com'
            and record.get('eventName') in _NAMES
            and record.get('eventType') == 'AwsApiCall'
            and record.get('eventCategory') == 'Management'
            and record.get('managementEvent') is True
            and record.get('readOnly') is False
            and not record.get('errorCode') and not record.get('errorMessage')
            and isinstance(record.get('requestParameters'), Mapping)
            and isinstance(record.get('recipientAccountId'), str)
            and re.fullmatch(r'\d{12}', record['recipientAccountId']) is not None)


def _actor(record: Mapping[str, Any]) -> str | None:
    identity = record.get('userIdentity')
    value = identity.get('arn') if isinstance(identity, Mapping) else None
    return value if isinstance(value, str) and value else None


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except ValueError:
        return None


def _event(record: Mapping[str, Any], target: str, flag: str) -> dict[str, Any]:
    return {
        'cloud.provider': 'aws', 'event.source': 'rds.amazonaws.com',
        'event.name': record['eventName'], 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': record['recipientAccountId'], 'actor.id': _actor(record),
        'target.id': target, f'request.{flag}': True,
    }


def normalize_aws_rds_restore_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if not _valid(record):
        return None
    req = record['requestParameters'];name = record['eventName']
    target = req.get('dBInstanceIdentifier')
    if not isinstance(target, str) or not target:
        return None
    if name == 'RestoreDBInstanceFromDBSnapshot':
        if req.get('publiclyAccessible') is True and isinstance(req.get('dBSnapshotIdentifier'), str) and req['dBSnapshotIdentifier']:
            return _event(record, target, 'rds_public_snapshot_clone_requested')
    elif name == 'ModifyDBInstance':
        if req.get('deletionProtection') is False:
            return _event(record, target, 'rds_deletion_protection_disabled')
    elif name == 'StopDBInstance':
        return _event(record, target, 'rds_instance_stop_requested')
    return None


def correlate_aws_rds_public_clone_password_reset(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    accepted = [r for r in records if _valid(r) and _actor(r) and _when(r.get('eventTime'))]
    restores = [r for r in accepted if r['eventName'] == 'RestoreDBInstanceFromDBSnapshot'
                and r['requestParameters'].get('publiclyAccessible') is True
                and isinstance(r['requestParameters'].get('dBInstanceIdentifier'), str)]
    out = []
    for current in accepted:
        if current['eventName'] != 'ModifyDBInstance':
            continue
        req = current['requestParameters']
        if (req.get('masterUserPassword') != 'HIDDEN_DUE_TO_SECURITY_REASONS'
                or req.get('applyImmediately') is not True
                or not isinstance(req.get('dBInstanceIdentifier'), str)):
            continue
        when = _when(current['eventTime'])
        prior = next((old for old in restores
                      if old['requestParameters']['dBInstanceIdentifier'] == req['dBInstanceIdentifier']
                      and old['recipientAccountId'] == current['recipientAccountId']
                      and _actor(old) == _actor(current)
                      and timedelta(0) <= when - _when(old['eventTime']) <= timedelta(hours=1)), None)
        if prior:
            event = _event(current, req['dBInstanceIdentifier'], 'rds_public_clone_password_reset_requested')
            event['correlation_evidence'] = {'restore_event_id': prior.get('eventID')}
            out.append(event)
    return out
