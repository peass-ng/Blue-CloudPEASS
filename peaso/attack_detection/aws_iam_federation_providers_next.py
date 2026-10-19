"""Normalize IAM federation provider creation and OIDC trust mutations."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any
from urllib.parse import urlparse


NAMES = {'CreateOpenIDConnectProvider', 'CreateSAMLProvider',
         'AddClientIDToOpenIDConnectProvider', 'UpdateOpenIDConnectProviderThumbprint'}


def normalize_aws_iam_federation_provider(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'iam.amazonaws.com' or name not in NAMES
            or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    account, request = record.get('recipientAccountId'), record.get('requestParameters')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account) or not isinstance(request, Mapping):
        return None
    response = record.get('responseElements')
    response = response if isinstance(response, Mapping) else {}
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or response.get('errorCode') or response.get('errorMessage'))
    oidc_prefix = f'arn:aws:iam::{account}:oidc-provider/'
    saml_prefix = f'arn:aws:iam::{account}:saml-provider/'
    target = request.get('openIDConnectProviderArn')
    valid_target = isinstance(target, str) and target.startswith(oidc_prefix) and len(target) > len(oidc_prefix)
    url = request.get('url')
    try:
        parsed = urlparse(url) if isinstance(url, str) else None
    except ValueError:
        parsed = None
    expected_oidc = (oidc_prefix + parsed.netloc + parsed.path.rstrip('/') if parsed is not None
                     and parsed.scheme == 'https' and parsed.netloc else None)
    client_ids = request.get('clientIDList')
    created_oidc = (name == 'CreateOpenIDConnectProvider' and expected_oidc is not None
                    and isinstance(client_ids, list) and bool(client_ids)
                    and all(isinstance(x, str) and bool(x) for x in client_ids)
                    and response.get('openIDConnectProviderArn') == expected_oidc)
    saml_name = request.get('name')
    created_saml = (name == 'CreateSAMLProvider' and isinstance(saml_name, str) and bool(saml_name)
                    and isinstance(request.get('sAMLMetadataDocument'), str)
                    and bool(request['sAMLMetadataDocument'])
                    and response.get('sAMLProviderArn') == saml_prefix + saml_name)
    client = request.get('clientID')
    audience_added = (name == 'AddClientIDToOpenIDConnectProvider' and valid_target
                      and isinstance(client, str) and bool(client))
    thumbs = request.get('thumbprintList')
    thumb_changed = (name == 'UpdateOpenIDConnectProviderThumbprint' and valid_target
                     and isinstance(thumbs, list) and 1 <= len(thumbs) <= 5
                     and all(isinstance(x, str) and re.fullmatch(r'[A-Fa-f0-9]{40}', x) for x in thumbs))
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': name, 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'),
            'target.id': expected_oidc if created_oidc else saml_prefix + saml_name if created_saml else target,
            'request.iam_oidc_provider_created': created_oidc and not failed,
            'request.iam_saml_provider_created': created_saml and not failed,
            'request.iam_oidc_client_id_added': audience_added and not failed,
            'request.iam_oidc_thumbprints_updated': thumb_changed and not failed}
