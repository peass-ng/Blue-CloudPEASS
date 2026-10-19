"""RDS log reads, public snapshot/instance settings and destructive deletion."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

_NAMES = {'DownloadDBLogFilePortion', 'ModifyDBSnapshotAttribute', 'ModifyDBInstance',
          'DeleteDBSnapshot', 'DeleteDBInstance'}


def normalize_aws_rds_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'rds.amazonaws.com' or name not in _NAMES
            or record.get('eventType') != 'AwsApiCall'
            or record.get('eventCategory') != 'Management'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not (name == 'DownloadDBLogFilePortion')
            or record.get('errorCode') or record.get('errorMessage')):
        return None
    request = record.get('requestParameters')
    if not isinstance(request, Mapping):
        return None
    account = record.get('recipientAccountId')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return None
    response = record.get('responseElements')
    response = response if isinstance(response, Mapping) else {}
    flag = None
    if name == 'DownloadDBLogFilePortion':
        target = request.get('dBInstanceIdentifier') or request.get('DBInstanceIdentifier')
        logfile = request.get('logFileName')
        if isinstance(target, str) and target and isinstance(logfile, str) and logfile:
            flag = 'rds_log_portion_read'
    elif name == 'ModifyDBSnapshotAttribute':
        target = request.get('dBSnapshotIdentifier') or request.get('DBSnapshotIdentifier')
        values = request.get('valuesToAdd')
        if (isinstance(target, str) and target and request.get('attributeName') == 'restore'
                and isinstance(values, list) and 'all' in values):
            flag = 'rds_snapshot_public_restore_added'
    elif name == 'ModifyDBInstance':
        target = request.get('dBInstanceIdentifier') or request.get('DBInstanceIdentifier')
        if isinstance(target, str) and target and request.get('publiclyAccessible') is True:
            flag = 'rds_instance_public_requested'
    elif name == 'DeleteDBSnapshot':
        target = request.get('dBSnapshotIdentifier') or request.get('DBSnapshotIdentifier')
        if isinstance(target, str) and target:
            flag = 'rds_snapshot_deleted'
    else:
        target = request.get('dBInstanceIdentifier') or request.get('DBInstanceIdentifier')
        if (isinstance(target, str) and target and request.get('skipFinalSnapshot') is True
                and request.get('deleteAutomatedBackups') is True):
            flag = 'rds_instance_deleted_without_backup'
    if flag is None:
        return None
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'rds.amazonaws.com',
        'event.name': name, 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity.get('arn'), 'target.id': target,
        f'request.{flag}': True,
    }
