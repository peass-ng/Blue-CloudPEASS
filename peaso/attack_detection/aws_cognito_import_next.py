"""Normalize Cognito user-import job creation and start events."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NAMES = {'CreateUserImportJob', 'StartUserImportJob'}


def normalize_aws_cognito_import(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if record.get('eventSource') != 'cognito-idp.amazonaws.com' or name not in NAMES:
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
    role = request.get('cloudWatchLogsRoleArn')
    role_ok = isinstance(role, str) and role.startswith(f'arn:aws:iam::{account}:role/')
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
        'event.name': name, 'event.outcome': 'failure' if failed else 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': actor.get('arn'), 'target.id': pool,
        'request.cognito_import_job_created': name == 'CreateUserImportJob' and isinstance(request.get('jobName'), str) and bool(request['jobName']) and role_ok and not failed,
        'request.cognito_import_job_started': name == 'StartUserImportJob' and isinstance(request.get('jobId'), str) and bool(request['jobId']) and not failed,
    }
