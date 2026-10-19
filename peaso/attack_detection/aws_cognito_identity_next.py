"""Normalize Cognito identity-pool and app-secret control-plane changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


IDENTITY_EVENTS = {'SetIdentityPoolRoles', 'UpdateIdentityPool', 'SetPrincipalTagAttributeMap'}
USER_POOL_EVENTS = {'AddUserPoolClientSecret'}
POOL_ID = re.compile(r'[a-z0-9-]+:[0-9a-f-]+\Z')
USER_POOL_ID = re.compile(r'[a-z0-9-]+_[A-Za-z0-9]+\Z')
MUTABLE_CLAIMS = {'nickname', 'preferred_username', 'website', 'profile', 'picture',
                  'zoneinfo', 'locale', 'address', 'phone_number', 'email'}


def normalize_aws_cognito_identity(record: Mapping[str, Any]) -> dict[str, Any] | None:
    source = record.get('eventSource')
    name = record.get('eventName')
    if not ((source == 'cognito-identity.amazonaws.com' and name in IDENTITY_EVENTS)
            or (source == 'cognito-idp.amazonaws.com' and name in USER_POOL_EVENTS)):
        return None
    if (record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    request = record.get('requestParameters')
    account = record.get('recipientAccountId')
    if not isinstance(request, Mapping) or not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return None
    pool = request.get('identityPoolId') if source == 'cognito-identity.amazonaws.com' else request.get('userPoolId')
    pattern = POOL_ID if source == 'cognito-identity.amazonaws.com' else USER_POOL_ID
    if not isinstance(pool, str) or not pattern.fullmatch(pool):
        return None
    response = record.get('responseElements')
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or isinstance(response, Mapping) and (response.get('errorCode') or response.get('errorMessage')))
    roles = request.get('roles')
    roles = roles if isinstance(roles, Mapping) else {}
    guest_role = roles.get('unauthenticated')
    auth_role = roles.get('authenticated')
    role_prefix = f'arn:aws:iam::{account}:role/'
    tags = request.get('principalTags')
    tags = tags if isinstance(tags, Mapping) else {}
    mutable_tag = any(isinstance(value, str) and value in MUTABLE_CLAIMS for value in tags.values())
    user = record.get('userIdentity')
    user = user if isinstance(user, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': source, 'event.name': name,
        'event.outcome': 'failure' if failed else 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': user.get('arn'), 'target.id': pool,
        'request.cognito_identity_guest_role_set': name == 'SetIdentityPoolRoles' and isinstance(guest_role, str) and guest_role.startswith(role_prefix) and not failed,
        'request.cognito_identity_auth_role_set': name == 'SetIdentityPoolRoles' and isinstance(auth_role, str) and auth_role.startswith(role_prefix) and not failed,
        'request.cognito_identity_guest_classic_enabled': name == 'UpdateIdentityPool' and request.get('allowUnauthenticatedIdentities') is True and request.get('allowClassicFlow') is True and not failed,
        'request.cognito_identity_mutable_principal_tag': name == 'SetPrincipalTagAttributeMap' and request.get('useDefaults') is False and mutable_tag and not failed,
        'request.cognito_user_pool_client_secret_added': name == 'AddUserPoolClientSecret' and isinstance(request.get('clientId'), str) and bool(request['clientId']) and not failed,
    }
