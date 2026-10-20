"""Security relevant RDS parameter group changes in CloudTrail management events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


def normalize_aws_rds_parameters(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource') != 'rds.amazonaws.com'
            or record.get('eventName') != 'ModifyDBParameterGroup'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('eventCategory') != 'Management'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not False
            or record.get('errorCode') or record.get('errorMessage')):
        return None
    account = record.get('recipientAccountId')
    request = record.get('requestParameters')
    response = record.get('responseElements')
    if (not isinstance(account, str) or re.fullmatch(r'\d{12}', account) is None
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)):
        return None
    group = request.get('dBParameterGroupName')
    if (not isinstance(group, str) or not group
            or response.get('dBParameterGroupName') != group):
        return None
    parameters = request.get('parameters')
    if not isinstance(parameters, list):
        return None
    values = {p.get('parameterName').lower(): str(p.get('parameterValue')).lower()
              for p in parameters if isinstance(p, Mapping)
              and isinstance(p.get('parameterName'), str)
              and isinstance(p.get('parameterValue'), (str, int))}
    logging = (values.get('log_statement') == 'all'
               or values.get('log_min_duration_statement') == '0'
               or (values.get('general_log') == '1' and values.get('log_output') == 'file'))
    tls_off = (values.get('rds.force_ssl') == '0'
               or values.get('require_secure_transport') in {'off', '0'})
    if not logging and not tls_off:
        return None
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'rds.amazonaws.com',
        'event.name': 'ModifyDBParameterGroup', 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity.get('arn'),
        'target.id': group,
        'request.rds_sql_logging_enabled': logging,
        'request.rds_tls_requirement_disabled': tls_off,
    }


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except ValueError:
        return None


def _accepted(record: Mapping[str, Any]) -> bool:
    name = record.get('eventName')
    return (record.get('eventSource') == 'rds.amazonaws.com'
            and name in {'ModifyDBParameterGroup', 'ModifyDBInstance',
                         'RebootDBInstance', 'DownloadDBLogFilePortion'}
            and record.get('eventType') == 'AwsApiCall'
            and record.get('eventCategory') == 'Management'
            and record.get('managementEvent') is True
            and record.get('readOnly') is (name == 'DownloadDBLogFilePortion')
            and not record.get('errorCode') and not record.get('errorMessage')
            and isinstance(record.get('requestParameters'), Mapping)
            and (name == 'DownloadDBLogFilePortion'
                 or isinstance(record.get('responseElements'), Mapping))
            and isinstance(record.get('recipientAccountId'), str)
            and re.fullmatch(r'\d{12}', record['recipientAccountId']) is not None
            and _time(record.get('eventTime')) is not None
            and isinstance(record.get('userIdentity'), Mapping)
            and isinstance(record['userIdentity'].get('arn'), str))


def correlate_aws_rds_sql_log_capture_path(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Correlate a logging change, attachment, reboot, then API log read."""
    accepted = [r for r in records if _accepted(r)]
    changed = [r for r in accepted if normalize_aws_rds_parameters(r)
               and normalize_aws_rds_parameters(r)['request.rds_sql_logging_enabled']]
    attached = [r for r in accepted if r['eventName'] == 'ModifyDBInstance'
                and isinstance(r['requestParameters'].get('dBParameterGroupName'), str)
                and isinstance(r['requestParameters'].get('dBInstanceIdentifier'), str)
                and r['responseElements'].get('dBInstanceIdentifier') == r['requestParameters']['dBInstanceIdentifier']]
    rebooted = [r for r in accepted if r['eventName'] == 'RebootDBInstance'
                and isinstance(r['requestParameters'].get('dBInstanceIdentifier'), str)
                and r['responseElements'].get('dBInstanceIdentifier') == r['requestParameters']['dBInstanceIdentifier']]
    out = []
    for current in accepted:
        if current['eventName'] != 'DownloadDBLogFilePortion':
            continue
        req = current['requestParameters'];db = req.get('dBInstanceIdentifier')
        if not isinstance(db, str) or not db or not isinstance(req.get('logFileName'), str) or not req['logFileName']:
            continue
        when = _time(current['eventTime'])
        actor = current['userIdentity']['arn'];account = current['recipientAccountId']
        for attach in attached:
            if (attach['requestParameters']['dBInstanceIdentifier'] != db
                    or attach['userIdentity']['arn'] != actor
                    or attach['recipientAccountId'] != account
                    or not timedelta(0) <= when - _time(attach['eventTime']) <= timedelta(hours=2)):
                continue
            group = attach['requestParameters']['dBParameterGroupName']
            change = next((r for r in changed
                           if r['requestParameters']['dBParameterGroupName'] == group
                           and r['userIdentity']['arn'] == actor and r['recipientAccountId'] == account
                           and timedelta(0) <= _time(attach['eventTime']) - _time(r['eventTime']) <= timedelta(hours=2)), None)
            reboot = next((r for r in rebooted
                           if r['requestParameters']['dBInstanceIdentifier'] == db
                           and r['userIdentity']['arn'] == actor and r['recipientAccountId'] == account
                           and timedelta(0) <= _time(r['eventTime']) - _time(attach['eventTime'])
                           and timedelta(0) <= when - _time(r['eventTime']) <= timedelta(hours=2)), None)
            if change and reboot:
                out.append({
                    'cloud.provider': 'aws', 'event.source': 'rds.amazonaws.com',
                    'event.name': 'DownloadDBLogFilePortion', 'event.outcome': 'success',
                    'event.id': current.get('eventID'), 'event.time': current.get('eventTime'),
                    'account.id': account, 'actor.id': actor, 'target.id': db,
                    'request.rds_sql_logging_then_log_read': True,
                    'correlation_evidence': {'parameter_change_event_id': change.get('eventID'),
                                             'attach_event_id': attach.get('eventID'),
                                             'reboot_event_id': reboot.get('eventID')},
                })
                break
    return out
