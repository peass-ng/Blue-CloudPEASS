"""Successful IAM MFA enrollment, deactivation, and resynchronization."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_iam_mfa_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get('eventSource') != 'iam.amazonaws.com' or record.get('eventName') not in {'EnableMFADevice', 'DeactivateMFADevice', 'ResyncMFADevice'}:
        return None
    if (record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    request = record.get('requestParameters')
    if not isinstance(request, Mapping):
        return None
    account = record.get('recipientAccountId')
    if not isinstance(account, str) or re.fullmatch(r'\d{12}', account) is None:
        return None
    username, serial = request.get('userName'), request.get('serialNumber')
    if not isinstance(username, str) or re.fullmatch(r'[A-Za-z0-9+=,.@_-]{1,64}', username) is None:
        return None
    if not isinstance(serial, str) or not serial:
        return None
    if serial.startswith('arn:'):
        if re.fullmatch(rf'arn:aws:iam::{account}:mfa/[A-Za-z0-9+=,.@_/-]+', serial) is None:
            return None
    elif re.fullmatch(r'[A-Za-z0-9_-]{1,256}', serial) is None:
        return None
    response = record.get('responseElements')
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or isinstance(response, Mapping) and (response.get('errorCode') or response.get('errorMessage')))
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    name = record['eventName']
    return {
        'cloud.provider': 'aws', 'event.source': 'iam.amazonaws.com',
        'event.name': name, 'event.outcome': 'failure' if failed else 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity.get('arn'), 'target.id': serial,
        'request.iam_mfa_resync_observed': not failed and name == 'ResyncMFADevice',
        'request.iam_mfa_enrolled': not failed and name == 'EnableMFADevice',
        'request.iam_mfa_deactivated': not failed and name == 'DeactivateMFADevice',
    }
