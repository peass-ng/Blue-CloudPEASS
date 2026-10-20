"""Normalize accepted EMR Serverless Spark runtime configuration changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_emr_serverless_runtime(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource') != 'emr-serverless.amazonaws.com'
            or record.get('eventName') != 'UpdateApplication'
            or record.get('eventCategory') != 'Management'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not False):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region):
        return None
    request, response = record.get('requestParameters'), record.get('responseElements')
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    application = response.get('application')
    if not isinstance(application, Mapping):
        return None
    app_id = request.get('applicationId')
    arn = f'arn:aws:emr-serverless:{region}:{account}:/applications/{app_id}'
    runtime = request.get('runtimeConfiguration')
    spark_defaults = (isinstance(runtime, list) and any(
        isinstance(item, Mapping) and item.get('classification') == 'spark-defaults'
        for item in runtime))
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or response.get('errorCode') or response.get('errorMessage'))
    accepted = (not failed and spark_defaults and isinstance(app_id, str)
                and bool(re.fullmatch(r'[0-9a-z]+', app_id))
                and application.get('applicationId') == app_id
                and application.get('arn') == arn
                and application.get('type') == 'Spark')
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': 'UpdateApplication',
            'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'),
            'target.id': arn if accepted else None,
            'request.emr_spark_defaults_updated': accepted}
