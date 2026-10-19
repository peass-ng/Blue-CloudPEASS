"""Normalize accepted IAM federation provider and audience removals."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NAMES = {'RemoveClientIDFromOpenIDConnectProvider', 'DeleteOpenIDConnectProvider', 'DeleteSAMLProvider'}


def normalize_aws_iam_federation_deletion(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'iam.amazonaws.com' or name not in NAMES
            or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    account, request = record.get('recipientAccountId'), record.get('requestParameters')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account) or not isinstance(request, Mapping):
        return None
    oidc = request.get('openIDConnectProviderArn')
    saml = request.get('sAMLProviderArn')
    valid_oidc = isinstance(oidc, str) and oidc.startswith(f'arn:aws:iam::{account}:oidc-provider/')
    valid_saml = isinstance(saml, str) and saml.startswith(f'arn:aws:iam::{account}:saml-provider/')
    client = request.get('clientID')
    audience_removed = (name == 'RemoveClientIDFromOpenIDConnectProvider' and valid_oidc
                        and isinstance(client, str) and bool(client))
    oidc_deleted = name == 'DeleteOpenIDConnectProvider' and valid_oidc
    saml_deleted = name == 'DeleteSAMLProvider' and valid_saml
    response = record.get('responseElements')
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or isinstance(response, Mapping) and (response.get('errorCode') or response.get('errorMessage')))
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': name, 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'), 'target.id': oidc if valid_oidc else saml,
            'request.iam_oidc_client_id_removed': audience_removed and not failed,
            'request.iam_oidc_provider_deleted': oidc_deleted and not failed,
            'request.iam_saml_provider_deleted': saml_deleted and not failed}
