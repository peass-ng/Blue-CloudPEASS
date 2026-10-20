"""Correlate SSM command enumeration with a later output-read request."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_NAMES = {'ListCommands', 'ListCommandInvocations', 'GetCommandInvocation'}
_UUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')
_NODE = re.compile(r'(?:i-(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{17})|mi-[0-9a-fA-F]{17})')


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except ValueError:
        return None


def _valid(record: Mapping[str, Any]) -> bool:
    return (record.get('eventSource') == 'ssm.amazonaws.com'
            and record.get('eventName') in _NAMES
            and record.get('eventCategory') == 'Management'
            and record.get('eventType') == 'AwsApiCall'
            and record.get('managementEvent') is True
            and record.get('readOnly') is True
            and not record.get('errorCode') and not record.get('errorMessage')
            and isinstance(record.get('requestParameters'), Mapping)
            and isinstance(record.get('recipientAccountId'), str)
            and re.fullmatch(r'\d{12}', record['recipientAccountId']) is not None)


def correlate_aws_ssm_command_output_read(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = []
    for record in records:
        if not _valid(record):
            continue
        when = _when(record.get('eventTime'))
        identity = record.get('userIdentity')
        actor = identity.get('arn') if isinstance(identity, Mapping) else None
        request = record['requestParameters']
        command = request.get('commandId')
        if (when is None or not isinstance(actor, str)
                or command is not None and (not isinstance(command, str) or _UUID.fullmatch(command) is None)):
            continue
        node = request.get('instanceId')
        if record['eventName'] == 'GetCommandInvocation':
            if command is None or not isinstance(node, str) or _NODE.fullmatch(node) is None:
                continue
        ordered.append((when, record['recipientAccountId'], actor, record['eventName'], command, node, record))
    ordered.sort(key=lambda item: item[0])
    prior: dict[tuple[str, str], list[tuple]] = {}
    matches = []
    for current in ordered:
        when, account, actor, name, command, node, event = current
        key = (account, actor)
        if name == 'GetCommandInvocation':
            earlier = next((old for old in reversed(prior.get(key, []))
                            if old[3] in {'ListCommands', 'ListCommandInvocations'}
                            and when - old[0] <= timedelta(minutes=10)
                            and (old[4] is None or old[4] == command)), None)
            if earlier:
                matches.append({
                    'cloud.provider': 'aws', 'event.source': 'ssm.amazonaws.com',
                    'event.name': 'GetCommandInvocation', 'event.outcome': 'success',
                    'event.id': event.get('eventID'), 'event.time': event.get('eventTime'),
                    'account.id': account, 'actor.id': actor, 'target.id': node,
                    'request.ssm_command_output_read_after_enumeration': True,
                    'correlation_evidence': {'enumeration_event_id': earlier[6].get('eventID')},
                })
        else:
            prior.setdefault(key, []).append(current)
    return matches
