"""Public RDS read replica, password reset and promotion control plane sequence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_NAMES = {'CreateDBInstanceReadReplica', 'ModifyDBInstance', 'PromoteReadReplica'}


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except ValueError:
        return None


def _accepted(record: Mapping[str, Any]) -> bool:
    return (record.get('eventSource') == 'rds.amazonaws.com'
            and record.get('eventName') in _NAMES
            and record.get('eventType') == 'AwsApiCall'
            and record.get('eventCategory') == 'Management'
            and record.get('managementEvent') is True
            and record.get('readOnly') is False
            and not record.get('errorCode') and not record.get('errorMessage')
            and isinstance(record.get('requestParameters'), Mapping)
            and isinstance(record.get('responseElements'), Mapping)
            and isinstance(record.get('recipientAccountId'), str)
            and re.fullmatch(r'\d{12}', record['recipientAccountId']) is not None
            and isinstance(record.get('userIdentity'), Mapping)
            and isinstance(record['userIdentity'].get('arn'), str)
            and _when(record.get('eventTime')) is not None)


def _public_replica(record: Mapping[str, Any]) -> bool:
    if not _accepted(record) or record['eventName'] != 'CreateDBInstanceReadReplica':
        return False
    request = record['requestParameters'];response = record['responseElements']
    target = request.get('dBInstanceIdentifier');source = request.get('sourceDBInstanceIdentifier')
    return (isinstance(target, str) and bool(target)
            and isinstance(source, str) and bool(source) and target != source
            and request.get('publiclyAccessible') is True
            and response.get('dBInstanceIdentifier') == target
            and response.get('readReplicaSourceDBInstanceIdentifier') == source
            and response.get('publiclyAccessible') is True)


def _event(record: Mapping[str, Any], target: str, flag: str) -> dict[str, Any]:
    return {'cloud.provider': 'aws', 'event.source': 'rds.amazonaws.com',
            'event.name': record['eventName'], 'event.outcome': 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': record['recipientAccountId'],
            'actor.id': record['userIdentity']['arn'], 'target.id': target,
            f'request.{flag}': True}


def normalize_aws_rds_public_replica(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if _public_replica(record):
        return _event(record, record['requestParameters']['dBInstanceIdentifier'],
                      'rds_public_read_replica_requested')
    return None


def correlate_aws_rds_public_replica_controls(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    accepted = [r for r in records if _accepted(r)]
    public = [r for r in accepted if _public_replica(r)]
    resets = [r for r in accepted if r['eventName'] == 'ModifyDBInstance'
              and r['requestParameters'].get('masterUserPassword') == 'HIDDEN_DUE_TO_SECURITY_REASONS'
              and r['requestParameters'].get('applyImmediately') is True
              and isinstance(r['requestParameters'].get('dBInstanceIdentifier'), str)
              and r['responseElements'].get('dBInstanceIdentifier') == r['requestParameters']['dBInstanceIdentifier']]
    out = []
    joined_resets = []
    for reset in resets:
        target = reset['requestParameters']['dBInstanceIdentifier']
        prior = next((r for r in public
                      if r['requestParameters']['dBInstanceIdentifier'] == target
                      and r['recipientAccountId'] == reset['recipientAccountId']
                      and r['userIdentity']['arn'] == reset['userIdentity']['arn']
                      and timedelta(0) <= _when(reset['eventTime']) - _when(r['eventTime']) <= timedelta(hours=1)), None)
        if prior:
            event = _event(reset, target, 'rds_public_replica_password_reset_requested')
            event['correlation_evidence'] = {'create_replica_event_id': prior.get('eventID')}
            out.append(event)
            joined_resets.append(reset)
    for promotion in accepted:
        if promotion['eventName'] != 'PromoteReadReplica':
            continue
        target = promotion['requestParameters'].get('dBInstanceIdentifier')
        if not isinstance(target, str) or promotion['responseElements'].get('dBInstanceIdentifier') != target:
            continue
        prior = next((r for r in joined_resets
                      if r['requestParameters']['dBInstanceIdentifier'] == target
                      and r['recipientAccountId'] == promotion['recipientAccountId']
                      and r['userIdentity']['arn'] == promotion['userIdentity']['arn']
                      and timedelta(0) <= _when(promotion['eventTime']) - _when(r['eventTime']) <= timedelta(hours=1)), None)
        if prior:
            event = _event(promotion, target, 'rds_public_replica_promoted_after_reset_requested')
            event['correlation_evidence'] = {'password_reset_event_id': prior.get('eventID')}
            out.append(event)
    return out
