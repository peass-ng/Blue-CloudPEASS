"""Normalize Cognito user and external identity-provider changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


EVENTS = {'AdminConfirmSignUp', 'AdminUpdateUserAttributes', 'AdminInitiateAuth',
          'CreateIdentityProvider', 'UpdateIdentityProvider', 'AdminLinkProviderForUser'}


def normalize_aws_cognito_federation(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if record.get('eventSource') != 'cognito-idp.amazonaws.com' or name not in EVENTS:
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
    source_user = request.get('sourceUser')
    source_user = source_user if isinstance(source_user, Mapping) else {}
    destination = request.get('destinationUser')
    destination = destination if isinstance(destination, Mapping) else {}
    details = request.get('providerDetails')
    details = details if isinstance(details, Mapping) else {}
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    provider = request.get('providerName')
    return {
        'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
        'event.name': name, 'event.outcome': 'failure' if failed else 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': actor.get('arn'), 'target.id': pool,
        'request.cognito_admin_confirm_signup': name == 'AdminConfirmSignUp' and not failed,
        'request.cognito_admin_update_user_attributes': name == 'AdminUpdateUserAttributes' and not failed,
        'request.cognito_admin_password_auth': name == 'AdminInitiateAuth' and request.get('authFlow') == 'ADMIN_USER_PASSWORD_AUTH' and isinstance(request.get('clientId'), str) and not failed,
        'request.cognito_external_idp_created': name == 'CreateIdentityProvider' and isinstance(provider, str) and bool(provider) and request.get('providerType') in {'OIDC', 'SAML', 'Google', 'Facebook', 'LoginWithAmazon', 'SignInWithApple'} and not failed,
        'request.cognito_external_idp_updated': name == 'UpdateIdentityProvider' and isinstance(provider, str) and bool(provider) and bool(details) and not failed,
        'request.cognito_external_identity_linked': name == 'AdminLinkProviderForUser' and destination.get('providerName') == 'Cognito' and isinstance(source_user.get('providerName'), str) and source_user['providerName'] != 'Cognito' and not failed,
    }
