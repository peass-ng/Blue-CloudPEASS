"""Detect broad, open-ended AWS Support permits from CloudTrail."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_support_permit(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource') != 'supportauthz.amazonaws.com'
            or record.get('eventName') != 'CreateSupportPermit'
            or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    request, response = record.get('requestParameters'), record.get('responseElements')
    if (not isinstance(account, str) or not re.fullmatch(r'\d{12}', account)
            or not isinstance(region, str) or not region or not isinstance(request, Mapping)
            or not isinstance(response, Mapping)):
        return None
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or response.get('errorCode') or response.get('errorMessage'))
    permit = request.get('permit')
    actions = permit.get('actions') if isinstance(permit, Mapping) else None
    resources = permit.get('resources') if isinstance(permit, Mapping) else None
    broad = (isinstance(actions, Mapping) and 'allActions' in actions
             and isinstance(actions['allActions'], Mapping)
             and isinstance(resources, Mapping) and 'allResourcesInRegion' in resources
             and isinstance(resources['allResourcesInRegion'], Mapping))
    conditions = permit.get('conditions') if isinstance(permit, Mapping) else None
    no_expiry = conditions is None or conditions == []
    no_case = not request.get('supportCaseDisplayId')
    arn = response.get('arn')
    confirmed = (isinstance(arn, str)
                 and arn.startswith(f'arn:aws:supportauthz:{region}:{account}:supportpermit/')
                 and response.get('status') == 'ACTIVE'
                 and response.get('name') == request.get('name'))
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': record.get('eventName'), 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'), 'target.id': arn,
            'request.support_permit_broad_open_ended': broad and no_expiry and no_case and confirmed and not failed}
