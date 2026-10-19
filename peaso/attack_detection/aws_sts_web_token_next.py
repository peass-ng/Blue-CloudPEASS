"""Normalize account-level outbound federation and external JWT issuance."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_sts_web_token(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name, source = record.get('eventName'), record.get('eventSource')
    enabled = name == 'EnableOutboundWebIdentityFederation' and source == 'iam.amazonaws.com'
    issued = name == 'GetWebIdentityToken' and source == 'sts.amazonaws.com'
    if not (enabled or issued) or (record.get('eventCategory') != 'Management'
            or record.get('eventType') != 'AwsApiCall' or record.get('managementEvent') is not True
            or record.get('readOnly') is not False):
        return None
    account, response = record.get('recipientAccountId'), record.get('responseElements')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account) or not isinstance(response, Mapping):
        return None
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or response.get('errorCode') or response.get('errorMessage'))
    request = record.get('requestParameters')
    audience = request.get('audience') if isinstance(request, Mapping) else None
    good_audience = isinstance(audience, list) and 1 <= len(audience) <= 10 and all(isinstance(x, str) and bool(x) for x in audience)
    enable_signal = enabled and isinstance(response.get('issuerIdentifier'), str) and bool(response['issuerIdentifier'])
    issuance_signal = (issued and good_audience and isinstance(response.get('webIdentityTokenId'), str)
                       and bool(response['webIdentityTokenId']) and bool(response.get('expiration')))
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': source, 'event.name': name,
            'event.outcome': 'failure' if failed else 'success', 'event.id': record.get('eventID'),
            'event.time': record.get('eventTime'), 'account.id': account,
            'actor.id': actor.get('arn'), 'target.id': account,
            'request.sts_outbound_web_federation_enabled': enable_signal and not failed,
            'request.sts_web_identity_token_issued': issuance_signal and not failed}
