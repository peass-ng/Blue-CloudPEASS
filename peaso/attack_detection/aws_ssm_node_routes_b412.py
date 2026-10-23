"""Accepted SSM shell command and cross-principal session resume signals."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r'[0-9]{12}\Z')
_REGION = re.compile(r'[a-z]{2}(?:-[a-z]+)+-[0-9]\Z')
_NODE = re.compile(r'(?:i-[0-9a-f]{8,17}|mi-[0-9a-f]{17})\Z')
_UUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')
_SESSION = re.compile(r'[A-Za-z0-9_+=,.@-]{1,96}\Z')


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _base(record: Mapping[str, Any], names: set[str]) -> tuple[str, str, str, Mapping[str, Any], Mapping[str, Any], datetime] | None:
    if (record.get('eventSource') != 'ssm.amazonaws.com'
            or record.get('eventName') not in names
            or record.get('eventType') != 'AwsApiCall'
            or record.get('eventCategory') != 'Management'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not False
            or record.get('errorCode') or record.get('errorMessage')):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    identity, request, response = (record.get(key) for key in
                                   ('userIdentity', 'requestParameters', 'responseElements'))
    when = _time(record.get('eventTime'))
    if (not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None
            or not isinstance(region, str) or _REGION.fullmatch(region) is None
            or not isinstance(identity, Mapping) or identity.get('accountId') != account
            or identity.get('type') == 'AWSService'
            or not isinstance(identity.get('arn'), str) or not identity['arn']
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(record.get('eventID'), str) or not record['eventID']
            or when is None):
        return None
    return account, region, identity['arn'], request, response, when


def _target(account: str, region: str, value: str) -> str:
    return 'sha256:' + hashlib.sha256(f'{account}:{region}:{value}'.encode()).hexdigest()[:24]


def normalize_shell_command(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Flag an accepted AWS-RunShellScript request to one explicit managed node."""
    base = _base(record, {'SendCommand'})
    if base is None:
        return None
    account, region, actor, request, response, _ = base
    nodes = request.get('instanceIds')
    command = response.get('command')
    if (request.get('documentName') != 'AWS-RunShellScript'
            or not isinstance(nodes, list) or len(nodes) != 1
            or not isinstance(nodes[0], str) or _NODE.fullmatch(nodes[0]) is None
            or not isinstance(command, Mapping)
            or command.get('documentName') != 'AWS-RunShellScript'
            or command.get('instanceIds') != nodes
            or not isinstance(command.get('commandId'), str)
            or _UUID.fullmatch(command['commandId']) is None):
        return None
    return {
        'cloud.provider': 'aws', 'event.source': 'ssm.amazonaws.com',
        'event.name': 'SendCommand', 'event.outcome': 'success',
        'event.id': record['eventID'], 'event.time': record['eventTime'],
        'account.id': account, 'actor.id': actor,
        'target.id': _target(account, region, nodes[0]),
        'request.ssm_shell_command_sent': True,
    }


def correlate_cross_principal_resume(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Match an accepted ResumeSession to a StartSession by another principal."""
    starts: dict[tuple[str, str, str], tuple[datetime, str, str, str]] = {}
    events = []
    for record in records:
        base = _base(record, {'StartSession', 'ResumeSession'})
        if base is not None:
            events.append((base[5], record, base))
    events.sort(key=lambda item: item[0])
    out = []
    seen: set[str] = set()
    for when, record, base in events:
        account, region, actor, request, response, _ = base
        if record['eventName'] == 'StartSession':
            node, session = request.get('target'), response.get('sessionId')
            if (isinstance(node, str) and _NODE.fullmatch(node)
                    and isinstance(session, str) and _SESSION.fullmatch(session)):
                starts[(account, region, session)] = when, actor, node, record['eventID']
            continue
        session = request.get('sessionId')
        if (not isinstance(session, str) or _SESSION.fullmatch(session) is None
                or response.get('sessionId') != session
                or record['eventID'] in seen):
            continue
        prior = starts.get((account, region, session))
        if (prior is None or prior[1] == actor
                or not timedelta(0) <= when - prior[0] <= timedelta(hours=24)):
            continue
        seen.add(record['eventID'])
        out.append({
            'cloud.provider': 'aws', 'event.source': 'ssm.amazonaws.com',
            'event.name': 'ResumeSession', 'event.outcome': 'success',
            'event.id': record['eventID'], 'event.time': record['eventTime'],
            'account.id': account, 'actor.id': actor,
            'target.id': _target(account, region, prior[2]),
            'request.ssm_session_resumed_by_other_principal': True,
            'correlation_evidence': {'start_event_id': prior[3]},
        })
    return out
