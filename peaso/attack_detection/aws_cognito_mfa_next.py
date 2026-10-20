"""Normalize Cognito administrator changes to an enrolled software MFA factor."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NAMES = {'AdminSetUserMFAPreference', 'AdminDeleteSoftwareToken'}


def normalize_aws_cognito_mfa(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if record.get('eventSource') != 'cognito-idp.amazonaws.com' or name not in NAMES:
        return None
    if (record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    request = record.get('requestParameters')
    account = record.get('recipientAccountId')
    if not isinstance(request, Mapping) or not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return None
    pool = request.get('userPoolId')
    if not isinstance(pool, str) or not re.fullmatch(r'[a-z0-9-]+_[A-Za-z0-9]+', pool):
        return None
    response = record.get('responseElements')
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or isinstance(response, Mapping) and (response.get('errorCode') or response.get('errorMessage')))
    settings = request.get('softwareTokenMfaSettings')
    settings = settings if isinstance(settings, Mapping) else {}
    user = record.get('userIdentity')
    user = user if isinstance(user, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
        'event.name': name, 'event.outcome': 'failure' if failed else 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': user.get('arn'), 'target.id': pool,
        'request.cognito_software_mfa_disabled': name == 'AdminSetUserMFAPreference' and settings.get('enabled') is False and not failed,
        'request.cognito_software_token_deleted': name == 'AdminDeleteSoftwareToken' and not failed,
    }
