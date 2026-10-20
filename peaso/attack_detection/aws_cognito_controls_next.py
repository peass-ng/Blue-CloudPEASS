"""Normalize Cognito user-pool control changes visible in CloudTrail."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NAMES = {'AdminCreateUser', 'AdminSetUserPassword', 'CreateGroup', 'UpdateGroup',
         'CreateUserPoolClient', 'UpdateUserPoolClient', 'SetUserPoolMfaConfig',
         'SetRiskConfiguration', 'AdminDisableUser', 'AdminEnableUser'}


def normalize_aws_cognito_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
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
    credentials = request.get('compromisedCredentialsRiskConfiguration')
    credentials = credentials if isinstance(credentials, Mapping) else {}
    actions = credentials.get('actions')
    actions = actions if isinstance(actions, Mapping) else {}
    validity = request.get('refreshTokenValidity')
    units = request.get('tokenValidityUnits')
    units = units if isinstance(units, Mapping) else {}
    refresh_unit = units.get('refreshToken', 'days')
    long_refresh = (isinstance(validity, int) and not isinstance(validity, bool)
                    and (refresh_unit == 'days' and validity >= 365
                         or refresh_unit == 'hours' and validity >= 8760
                         or refresh_unit == 'minutes' and validity >= 525600
                         or refresh_unit == 'seconds' and validity >= 31536000))
    role = request.get('roleArn')
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': name, 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': identity.get('arn'), 'target.id': pool,
            'request.cognito_suppressed_admin_user': name == 'AdminCreateUser' and request.get('messageAction') == 'SUPPRESS' and not failed,
            'request.cognito_permanent_password_set': name == 'AdminSetUserPassword' and request.get('permanent') is True and not failed,
            'request.cognito_group_role_set': name in {'CreateGroup', 'UpdateGroup'} and isinstance(request.get('groupName'), str) and bool(request['groupName']) and isinstance(role, str) and role.startswith(f'arn:aws:iam::{account}:role/') and not failed,
            'request.cognito_long_refresh_no_revocation': name in {'CreateUserPoolClient', 'UpdateUserPoolClient'} and long_refresh and request.get('enableTokenRevocation') is False and not failed,
            'request.cognito_mfa_off': name == 'SetUserPoolMfaConfig' and request.get('mfaConfiguration') == 'OFF' and not failed,
            'request.cognito_compromised_credentials_no_action': name == 'SetRiskConfiguration' and actions.get('eventAction') == 'NO_ACTION' and isinstance(credentials.get('eventFilter'), list) and bool(credentials['eventFilter']) and not failed,
            'request.cognito_user_disabled': name == 'AdminDisableUser' and not failed,
            'request.cognito_user_enabled': name == 'AdminEnableUser' and not failed,
    }
