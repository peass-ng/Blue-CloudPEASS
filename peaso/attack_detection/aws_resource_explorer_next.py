"""Normalize Resource Explorer view writes observed in CloudTrail."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NAMES = {'UpdateView', 'AssociateDefaultView', 'DeleteView'}


def normalize_aws_resource_explorer_view(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'resource-explorer-2.amazonaws.com' or name not in NAMES
            or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region):
        return None
    request, response = record.get('requestParameters'), record.get('responseElements')
    if not isinstance(request, Mapping):
        return None
    view = request.get('ViewArn')
    valid = (isinstance(view, str) and view.startswith(f'arn:aws:resource-explorer-2:{region}:{account}:view/')
             and len(view.split('/')) == 3 and bool(view.split('/')[1]) and bool(view.split('/')[2]))
    response_view = response.get('View') if isinstance(response, Mapping) else None
    returned = (response_view.get('ViewArn') if isinstance(response_view, Mapping) else
                response.get('ViewArn') if isinstance(response, Mapping) else None)
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or isinstance(response, Mapping) and (response.get('errorCode') or response.get('errorMessage')))
    accepted = valid and returned == view and not failed
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': name, 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'), 'target.id': view if valid else None,
            'request.resource_explorer_view_updated': accepted and name == 'UpdateView',
            'request.resource_explorer_default_associated': accepted and name == 'AssociateDefaultView',
            'request.resource_explorer_view_deleted': accepted and name == 'DeleteView'}
