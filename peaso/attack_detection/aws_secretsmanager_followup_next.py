"""Normalize observable Secrets Manager access and lifecycle changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NAMES = {'BatchGetSecretValue', 'PutSecretValue', 'UpdateSecret',
         'DeleteSecret', 'RestoreSecret'}


def _secret_arn(value: Any, region: str, account: str | None = None) -> bool:
    if not isinstance(value, str):
        return False
    scope = re.escape(account) if account else r'\d{12}'
    return bool(re.fullmatch(
        rf'arn:aws:secretsmanager:{re.escape(region)}:{scope}:secret:[A-Za-z0-9/_+=.@-]+', value))


def normalize_aws_secretsmanager_followup(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'secretsmanager.amazonaws.com' or name not in NAMES
            or record.get('eventCategory') != 'Management'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not (name == 'BatchGetSecretValue')):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region):
        return None
    request = record.get('requestParameters')
    if not isinstance(request, Mapping):
        return None
    response = record.get('responseElements')
    response = response if isinstance(response, Mapping) else {}
    arn = request.get('secretId')
    own_secret = _secret_arn(arn, region, account)
    accepted = not (record.get('errorCode') or record.get('errorMessage')
                    or response.get('errorCode') or response.get('errorMessage'))
    confirmed = own_secret and response.get('arn') == arn
    batch = request.get('secretIdList')
    multi = (isinstance(batch, list) and len(batch) >= 2
             and len(batch) == len(set(str(item) for item in batch))
             and all(_secret_arn(item, region) for item in batch))
    stages = request.get('versionStages')
    current = stages is None or (isinstance(stages, list) and 'AWSCURRENT' in stages)
    key = request.get('kmsKeyId')
    valid_key = isinstance(key, str) and bool(re.fullmatch(
        rf'arn:aws:kms:{re.escape(region)}:{account}:key/[a-f0-9-]{{36}}', key))
    window = request.get('recoveryWindowInDays')
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'secretsmanager.amazonaws.com',
        'event.name': name, 'event.outcome': 'success' if accepted else 'failure',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity.get('arn'),
        'target.id': arn if own_secret else None,
        'request.secret_batch_multi_read_requested': bool(
            accepted and name == 'BatchGetSecretValue' and multi),
        'request.secret_current_value_written': bool(
            accepted and name == 'PutSecretValue' and confirmed and current
            and isinstance(request.get('clientRequestToken'), str)),
        'request.secret_kms_key_associated': bool(
            accepted and name == 'UpdateSecret' and confirmed and valid_key),
        'request.secret_deletion_scheduled': bool(
            accepted and name == 'DeleteSecret' and confirmed
            and request.get('forceDeleteWithoutRecovery') is not True
            and type(window) is int and 7 <= window <= 30
            and isinstance(response.get('deletionDate'), (str, int, float))),
        'request.secret_restored': bool(
            accepted and name == 'RestoreSecret' and confirmed),
    }
