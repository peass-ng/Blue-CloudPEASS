"""Accepted Session Manager shell session starts on managed nodes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_NODE = re.compile(r'(?:i-(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{17})|mi-[0-9a-fA-F]{17})')


def normalize_aws_ssm_session_start(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource') != 'ssm.amazonaws.com'
            or record.get('eventName') != 'StartSession'
            or record.get('eventCategory') != 'Management'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not False):
        return None
    request, response = record.get('requestParameters'), record.get('responseElements')
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    target, session_id = request.get('target'), response.get('sessionId')
    if (not isinstance(target, str) or _NODE.fullmatch(target) is None
            or not isinstance(session_id, str) or not session_id
            or not isinstance(record.get('recipientAccountId'), str)
            or re.fullmatch(r'\d{12}', record['recipientAccountId']) is None):
        return None
    failed = bool(record.get('errorCode') or record.get('errorMessage'))
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'ssm.amazonaws.com',
        'event.name': 'StartSession', 'event.outcome': 'failure' if failed else 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': record['recipientAccountId'], 'actor.id': identity.get('arn'),
        'target.id': target, 'request.ssm_session_started': not failed,
    }
