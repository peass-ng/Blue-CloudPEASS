"""Correlate Glue job script configuration with nearby run requests."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def correlate_aws_glue_job_script_runs(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = []
    for record in records:
        if record.get('eventSource') != 'glue.amazonaws.com' or record.get('eventName') not in {'CreateJob', 'UpdateJob', 'StartJobRun'}:
            continue
        if (record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
                or record.get('managementEvent') is not True or record.get('readOnly') is not False
                or record.get('errorCode') or record.get('errorMessage')):
            continue
        response = record.get('responseElements')
        if isinstance(response, Mapping) and (response.get('errorCode') or response.get('errorMessage')):
            continue
        when = _when(record.get('eventTime'))
        request = record.get('requestParameters')
        identity = record.get('userIdentity')
        account = record.get('recipientAccountId')
        region = record.get('awsRegion')
        if (when is None or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
                or not isinstance(identity.get('arn'), str) or not isinstance(account, str)
                or len(account) != 12 or not account.isdigit() or identity.get('accountId') != account
                or not isinstance(region, str) or not region):
            continue
        name = request.get('name') if record['eventName'] == 'CreateJob' else request.get('jobName')
        if not isinstance(name, str) or not name:
            continue
        ordered.append((when, 1 if record['eventName'] == 'StartJobRun' else 0, account, region, name, record))
    ordered.sort(key=lambda item: item[:5])
    configured: dict[tuple[str, str, str], tuple[datetime, Mapping[str, Any], str]] = {}
    matches = []
    for when, _, account, region, name, record in ordered:
        key = (account, region, name)
        if record['eventName'] in {'CreateJob', 'UpdateJob'}:
            request = record['requestParameters']
            config = request if record['eventName'] == 'CreateJob' else request.get('jobUpdate')
            if not isinstance(config, Mapping):
                continue
            command = config.get('command')
            role = config.get('role')
            if (isinstance(command, Mapping) and isinstance(command.get('scriptLocation'), str)
                    and command['scriptLocation'].startswith('s3://')
                    and isinstance(role, str) and role.startswith(f'arn:aws:iam::{account}:role/')):
                configured[key] = (when, record, command['scriptLocation'])
            continue
        previous = configured.get(key)
        if previous is None or when - previous[0] > timedelta(minutes=30):
            continue
        _, config_event, script = previous
        matches.append({
            'cloud.provider': 'aws', 'event.source': 'glue.amazonaws.com',
            'event.name': 'StartJobRun', 'event.outcome': 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': record['userIdentity']['arn'], 'target.id': name,
            'request.glue_job_run_after_script_set': True,
            'correlation_evidence': {'configuration_event_id': config_event.get('eventID'),
                                     'configuration_event_name': config_event.get('eventName'),
                                     'script_location': script},
        })
    return matches
