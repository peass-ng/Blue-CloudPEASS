"""Account-wide Direct Connect virtual-interface inventory reads."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r'[0-9]{12}\Z')
_REGION = re.compile(r'[a-z]{2}(?:-[a-z]+)+-[0-9]\Z')


def _time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.tzinfo is not None
    except ValueError:
        return False


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report an accepted unscoped inventory call without response contents."""
    if (record.get('eventSource') != 'directconnect.amazonaws.com'
            or record.get('eventName') != 'DescribeVirtualInterfaces'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('eventCategory') != 'Management'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not True
            or record.get('errorCode') or record.get('errorMessage')):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    identity, request = record.get('userIdentity'), record.get('requestParameters')
    if (not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None
            or not isinstance(region, str) or _REGION.fullmatch(region) is None
            or not isinstance(identity, Mapping) or identity.get('accountId') != account
            or identity.get('type') == 'AWSService'
            or not isinstance(identity.get('arn'), str) or not identity['arn']
            or request not in (None, {})
            or not isinstance(record.get('eventID'), str) or not record['eventID']
            or not _time(record.get('eventTime'))):
        return None
    target = 'sha256:' + hashlib.sha256(
        f'{account}:{region}:all-direct-connect-virtual-interfaces'.encode()).hexdigest()[:24]
    return {
        'cloud.provider': 'aws', 'event.source': 'directconnect.amazonaws.com',
        'event.name': 'DescribeVirtualInterfaces', 'event.outcome': 'success',
        'event.id': record['eventID'], 'event.time': record['eventTime'],
        'account.id': account, 'actor.id': identity['arn'], 'target.id': target,
        'request.directconnect_virtual_interfaces_enumerated': True,
    }
