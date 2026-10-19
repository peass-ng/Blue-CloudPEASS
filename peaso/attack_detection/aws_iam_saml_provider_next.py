"""Normalize accepted IAM SAML provider metadata replacement."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_iam_saml_provider_update(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource') != 'iam.amazonaws.com'
            or record.get('eventName') != 'UpdateSAMLProvider'
            or record.get('eventCategory') != 'Management'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not False):
        return None
    account = record.get('recipientAccountId')
    request, response = record.get('requestParameters'), record.get('responseElements')
    if (not isinstance(account, str) or not re.fullmatch(r'\d{12}', account)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)):
        return None
    target = request.get('sAMLProviderArn')
    submitted = request.get('sAMLMetadataDocument')
    replaced = (isinstance(target, str) and target.startswith(f'arn:aws:iam::{account}:saml-provider/')
                and isinstance(submitted, str) and bool(submitted)
                and response.get('sAMLProviderArn') == target)
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or response.get('errorCode') or response.get('errorMessage'))
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': record.get('eventName'), 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'), 'target.id': target,
            'request.iam_saml_provider_metadata_replaced': replaced and not failed}
