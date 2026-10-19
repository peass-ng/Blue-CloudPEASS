"""Identify Parameter Store history and recursive decrypted reads."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_ssm_parameter_read(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'ssm.amazonaws.com'
            or name not in {'GetParameterHistory', 'GetParametersByPath', 'GetParameter', 'GetParameters'}
            or record.get('eventCategory') != 'Management'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not True):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if (not isinstance(account, str) or re.fullmatch(r'\d{12}', account) is None
            or not isinstance(region, str)):
        return None
    request = record.get('requestParameters')
    if not isinstance(request, Mapping):
        return None
    target: str | None
    if name == 'GetParametersByPath':
        target = request.get('path')
        if not isinstance(target, str) or not re.fullmatch(r'/[A-Za-z0-9_.\-/]+', target):
            return None
    elif name == 'GetParameters':
        names = request.get('names')
        if (not isinstance(names, list) or not names or len(names) > 10
                or not all(isinstance(item, str) and re.fullmatch(r'/?[A-Za-z0-9_.\-/]+', item)
                           for item in names)):
            return None
        target = names[0] if len(names) == 1 else None
    else:
        target = request.get('name')
        if not isinstance(target, str) or not re.fullmatch(r'/?[A-Za-z0-9_.\-/]+', target):
            return None
    failed = bool(record.get('errorCode') or record.get('errorMessage'))
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'ssm.amazonaws.com',
        'event.name': name, 'event.outcome': 'failure' if failed else 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity.get('arn'),
        'target.id': f'arn:aws:ssm:{region}:{account}:parameter/{target.lstrip("/")}' if target else None,
        'request.ssm_parameter_history_decrypted': bool(
            not failed and name == 'GetParameterHistory'
            and request.get('withDecryption') is True),
        'request.ssm_parameter_path_recursive_decrypted': bool(
            not failed and name == 'GetParametersByPath'
            and request.get('recursive') is True
            and request.get('withDecryption') is True),
        'request.ssm_parameter_current_decrypted': bool(
            not failed and name in {'GetParameter', 'GetParameters'}
            and request.get('withDecryption') is True),
    }
