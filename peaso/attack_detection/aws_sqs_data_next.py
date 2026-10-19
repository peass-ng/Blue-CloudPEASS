"""SQS data-event signal for prolonged message visibility."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def _queue(record: Mapping[str, Any]) -> str | None:
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if (not isinstance(account, str) or re.fullmatch(r'\d{12}', account) is None
            or not isinstance(region, str)):
        return None
    request = record.get('requestParameters')
    if not isinstance(request, Mapping):
        return None
    url = request.get('queueUrl')
    if not isinstance(url, str):
        return None
    match = re.fullmatch(
        rf'https://sqs\.{re.escape(region)}\.amazonaws\.com/{account}/([A-Za-z0-9_-]{{1,80}}(?:\.fifo)?)', url)
    if match is None:
        return None
    arn = f'arn:aws:sqs:{region}:{account}:{match.group(1)}'
    resources = record.get('resources')
    if not isinstance(resources, list) or not any(
            isinstance(item, Mapping) and item.get('type') == 'AWS::SQS::Queue'
            and item.get('ARN') == arn for item in resources):
        return None
    return arn


def _valid(record: Mapping[str, Any], names: set[str]) -> bool:
    return (record.get('eventSource') == 'sqs.amazonaws.com'
            and record.get('eventName') in names
            and record.get('eventCategory') == 'Data'
            and record.get('eventType') == 'AwsApiCall'
            and record.get('managementEvent') is False
            and record.get('readOnly') is False
            and not record.get('errorCode') and not record.get('errorMessage')
            and _queue(record) is not None)


def normalize_aws_sqs_data(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if not _valid(record, {'ChangeMessageVisibility'}):
        return None
    request = record['requestParameters']
    timeout = request.get('visibilityTimeout')
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'sqs.amazonaws.com',
        'event.name': 'ChangeMessageVisibility', 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': record['recipientAccountId'], 'actor.id': identity.get('arn'),
        'target.id': _queue(record),
        'request.sqs_message_hidden_over_hour': bool(
            type(timeout) is int and 3600 <= timeout <= 43200),
    }


def correlate_aws_sqs_fifo_dedup_collision(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Match accepted cross-actor FIFO sends without inferring which actor sent first."""
    ordered = []
    for record in records:
        if not _valid(record, {'SendMessage'}):
            continue
        when = _when(record.get('eventTime'))
        request, response = record['requestParameters'], record.get('responseElements')
        identity = record.get('userIdentity')
        if (when is None or not isinstance(response, Mapping)
                or not isinstance(identity, Mapping)
                or not isinstance(identity.get('arn'), str)):
            continue
        arn = _queue(record)
        dedup, group = request.get('messageDeduplicationId'), request.get('messageGroupId')
        message_id, body_hash = response.get('messageId'), response.get('mD5OfMessageBody')
        if (not arn or not arn.endswith('.fifo')
                or not isinstance(dedup, str) or not dedup
                or not isinstance(group, str) or not group
                or not isinstance(message_id, str) or not message_id
                or not isinstance(body_hash, str) or re.fullmatch(r'[0-9a-f]{32}', body_hash) is None):
            continue
        ordered.append((when, arn, dedup, group, message_id, body_hash, identity['arn'], record))
    ordered.sort(key=lambda item: item[0])
    prior: dict[tuple[str, str, str], list[tuple]] = {}
    results = []
    for current in ordered:
        when, arn, dedup, group, message_id, body_hash, actor, event = current
        key = (arn, dedup, group)
        for old in prior.get(key, []):
            if (when - old[0] <= timedelta(minutes=5)
                    and actor != old[6] and message_id == old[4]
                    and body_hash != old[5]):
                results.append({
                    'cloud.provider': 'aws', 'event.source': 'sqs.amazonaws.com',
                    'event.name': 'SendMessage', 'event.outcome': 'success',
                    'event.id': event.get('eventID'), 'event.time': event.get('eventTime'),
                    'account.id': event['recipientAccountId'], 'actor.id': actor,
                    'target.id': arn, 'request.sqs_fifo_cross_actor_dedup_collision': True,
                    'correlation_evidence': {'paired_send_event_id': old[7].get('eventID')},
                })
                break
        prior.setdefault(key, []).append(current)
    return results

