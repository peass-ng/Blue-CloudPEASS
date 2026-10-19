"""SSM hybrid activation, runbook, document-version and window signals."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_UUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')
_WINDOW = re.compile(r'mw-[0-9a-f]{17}')


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        when = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return when if when.tzinfo else None
    except ValueError:
        return None


def _valid(record: Mapping[str, Any]) -> bool:
    return (record.get('eventSource') == 'ssm.amazonaws.com'
            and record.get('eventType') == 'AwsApiCall'
            and record.get('eventCategory') == 'Management'
            and record.get('managementEvent') is True
            and record.get('readOnly') is False
            and not record.get('errorCode') and not record.get('errorMessage')
            and isinstance(record.get('requestParameters'), Mapping)
            and isinstance(record.get('recipientAccountId'), str)
            and re.fullmatch(r'\d{12}', record['recipientAccountId']) is not None)


def _actor(record: Mapping[str, Any]) -> str | None:
    identity = record.get('userIdentity')
    value = identity.get('arn') if isinstance(identity, Mapping) else None
    return value if isinstance(value, str) and value else None


def _event(record: Mapping[str, Any], target: str, flag: str) -> dict[str, Any]:
    return {
        'cloud.provider': 'aws', 'event.source': 'ssm.amazonaws.com',
        'event.name': record['eventName'], 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': record['recipientAccountId'], 'actor.id': _actor(record),
        'target.id': target, f'request.{flag}': True,
    }


def normalize_aws_ssm_automation_window(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if not _valid(record):
        return None
    req = record['requestParameters']
    response = record.get('responseElements')
    if not isinstance(response, Mapping):
        response = {}
    name = record.get('eventName')
    if name == 'CreateActivation':
        role, activation = req.get('iamRole'), response.get('activationId')
        if (isinstance(role, str) and role and isinstance(activation, str)
                and _UUID.fullmatch(activation) and type(req.get('registrationLimit')) is int
                and req['registrationLimit'] >= 1):
            return _event(record, activation, 'ssm_hybrid_activation_created')
    if name == 'StartAutomationExecution':
        document, execution = req.get('documentName'), response.get('automationExecutionId')
        if (isinstance(document, str) and document and isinstance(execution, str)
                and _UUID.fullmatch(execution)):
            return _event(record, document, 'ssm_automation_started')
    return None


def _target_ids(req: Mapping[str, Any]) -> set[str]:
    values: set[str] = set()
    for target in req.get('targets', []):
        if isinstance(target, Mapping) and target.get('key') == 'WindowTargetIds':
            seq = target.get('values')
            if isinstance(seq, list):
                values.update(x for x in seq if isinstance(x, str))
    return values


def correlate_aws_ssm_document_window(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    valid = [r for r in records if _valid(r) and _actor(r) and _time(r.get('eventTime'))]
    updates = [r for r in valid if r.get('eventName') == 'UpdateDocument'
               and isinstance(r['requestParameters'].get('name'), str)
               and r['requestParameters'].get('name')
               and isinstance(r.get('responseElements'), Mapping)
               and isinstance(r['responseElements'].get('documentDescription'), Mapping)
               and isinstance(r['responseElements']['documentDescription'].get('documentVersion'), str)]
    targets = [r for r in valid if r.get('eventName') == 'RegisterTargetWithMaintenanceWindow'
               and isinstance(r.get('responseElements'), Mapping)
               and isinstance(r['responseElements'].get('windowTargetId'), str)]
    out = []
    for current in valid:
        req = current['requestParameters'];name = current.get('eventName')
        when = _time(current['eventTime'])
        if name == 'UpdateDocumentDefaultVersion':
            doc, version = req.get('name'), req.get('documentVersion')
            if not isinstance(doc, str) or not doc or not isinstance(version, str) or not version.isdigit():
                continue
            earlier = next((r for r in updates if r['requestParameters']['name'] == doc
                            and r['responseElements']['documentDescription']['documentVersion'] == version
                            and r['recipientAccountId'] == current['recipientAccountId']
                            and _actor(r) == _actor(current)
                            and abs(when - _time(r['eventTime'])) <= timedelta(minutes=10)), None)
            if earlier:
                event = _event(current, doc, 'ssm_document_updated_and_default_promoted')
                event['correlation_evidence'] = {'update_event_id': earlier.get('eventID')}
                out.append(event)
        elif name == 'RegisterTaskWithMaintenanceWindow':
            window, task_type, task_arn = req.get('windowId'), req.get('taskType'), req.get('taskArn')
            if (not isinstance(window, str) or not _WINDOW.fullmatch(window)
                    or task_type != 'RUN_COMMAND' or not isinstance(task_arn, str) or not task_arn
                    or not isinstance(current.get('responseElements'), Mapping)
                    or not isinstance(current['responseElements'].get('windowTaskId'), str)):
                continue
            ids = _target_ids(req)
            earlier = next((r for r in targets if r['requestParameters'].get('windowId') == window
                            and r['responseElements']['windowTargetId'] in ids
                            and r['recipientAccountId'] == current['recipientAccountId']
                            and _actor(r) == _actor(current)
                            and timedelta(0) <= when - _time(r['eventTime']) <= timedelta(minutes=10)), None)
            if earlier:
                event = _event(current, window, 'ssm_window_target_then_command_task')
                event['correlation_evidence'] = {'target_event_id': earlier.get('eventID')}
                out.append(event)
    return out
