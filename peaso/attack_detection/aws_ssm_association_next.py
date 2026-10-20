"""One-time execution requests for existing SSM State Manager associations."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')


def normalize_aws_ssm_association_start(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource') != 'ssm.amazonaws.com'
            or record.get('eventName') != 'StartAssociationsOnce'
            or record.get('eventCategory') != 'Management'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not False):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account, str) or re.fullmatch(r'\d{12}', account) is None or not isinstance(region, str):
        return None
    request = record.get('requestParameters')
    if not isinstance(request, Mapping):
        return None
    ids = request.get('associationIds')
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 10
            or not all(isinstance(value, str) and _ID.fullmatch(value) for value in ids)):
        return None
    failed = bool(record.get('errorCode') or record.get('errorMessage'))
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'ssm.amazonaws.com',
        'event.name': 'StartAssociationsOnce', 'event.outcome': 'failure' if failed else 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity.get('arn'),
        'target.id': f'arn:aws:ssm:{region}:{account}:association/{ids[0]}' if len(ids) == 1 else None,
        'request.ssm_association_started_once': not failed,
        'request.ssm_association_count': len(ids),
    }
