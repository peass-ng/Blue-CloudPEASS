"""Observable Step Functions history reads and workflow control changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

_MACHINE = re.compile(r'arn:aws:states:([a-z0-9-]+):(\d{12}):stateMachine:[A-Za-z0-9+!@_.-]+')
_EXECUTION = re.compile(r'arn:aws:states:([a-z0-9-]+):(\d{12}):execution:[A-Za-z0-9+!@_.-]+:[A-Za-z0-9+!@_.-]+')
_NAMES = {'GetExecutionHistory', 'StopExecution', 'UpdateStateMachine', 'DeleteStateMachine'}


def normalize_aws_stepfunctions_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'states.amazonaws.com' or name not in _NAMES
            or record.get('eventType') != 'AwsApiCall'
            or record.get('eventCategory') != 'Management'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not (name == 'GetExecutionHistory')
            or record.get('errorCode') or record.get('errorMessage')):
        return None
    req = record.get('requestParameters')
    if not isinstance(req, Mapping):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account) or not isinstance(region, str):
        return None
    target = req.get('executionArn') if name in ('GetExecutionHistory', 'StopExecution') else req.get('stateMachineArn')
    pattern = _EXECUTION if name in ('GetExecutionHistory', 'StopExecution') else _MACHINE
    match = pattern.fullmatch(target) if isinstance(target, str) else None
    if not match or match.group(1) != region or match.group(2) != account:
        return None
    response = record.get('responseElements')
    response = response if isinstance(response, Mapping) else {}
    flag = {
        'GetExecutionHistory': 'sfn_execution_history_data_read',
        'StopExecution': 'sfn_execution_stopped',
        'UpdateStateMachine': 'sfn_definition_updated',
        'DeleteStateMachine': 'sfn_machine_deleted',
    }[name]
    if name == 'GetExecutionHistory' and req.get('includeExecutionData') is not True:
        return None
    if name == 'StopExecution' and not response.get('stopDate'):
        return None
    if name == 'UpdateStateMachine' and (req.get('definition') != 'HIDDEN_DUE_TO_SECURITY_REASONS'
                                         or not isinstance(response.get('revisionId'), str)):
        return None
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'states.amazonaws.com',
        'event.name': name, 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity.get('arn'), 'target.id': target,
        f'request.{flag}': True,
    }

_ALIAS = re.compile(r'arn:aws:states:([a-z0-9-]+):(\d{12}):stateMachine:([A-Za-z0-9+!@_.-]+):([A-Za-z][A-Za-z0-9+!@_.-]*)')
_VERSION = re.compile(r'arn:aws:states:([a-z0-9-]+):(\d{12}):stateMachine:([A-Za-z0-9+!@_.-]+):([1-9][0-9]*)')
_ALIAS_NAMES = {'SendTaskSuccess', 'UpdateStateMachineAlias', 'DeleteStateMachineAlias', 'DeleteStateMachineVersion'}


def normalize_aws_stepfunctions_activity_alias(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'states.amazonaws.com' or name not in _ALIAS_NAMES
            or record.get('eventType') != 'AwsApiCall'
            or record.get('eventCategory') != 'Management'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not False
            or record.get('errorCode') or record.get('errorMessage')):
        return None
    req = record.get('requestParameters')
    if not isinstance(req, Mapping):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account) or not isinstance(region, str):
        return None
    response = record.get('responseElements')
    response = response if isinstance(response, Mapping) else {}
    target = None
    if name == 'SendTaskSuccess':
        if (req.get('taskToken') != 'HIDDEN_DUE_TO_SECURITY_REASONS'
                or req.get('output') != 'HIDDEN_DUE_TO_SECURITY_REASONS'):
            return None
        flag = 'sfn_activity_callback_success'
    elif name in ('UpdateStateMachineAlias', 'DeleteStateMachineAlias'):
        target = req.get('stateMachineAliasArn')
        match = _ALIAS.fullmatch(target) if isinstance(target, str) else None
        if not match or match.group(1) != region or match.group(2) != account:
            return None
        if name == 'UpdateStateMachineAlias':
            routes = req.get('routingConfiguration')
            if not isinstance(routes, list) or len(routes) != 1 or not isinstance(routes[0], Mapping):
                return None
            version = routes[0].get('stateMachineVersionArn')
            vm = _VERSION.fullmatch(version) if isinstance(version, str) else None
            if (not vm or vm.group(1) != region or vm.group(2) != account
                    or vm.group(3) != match.group(3) or routes[0].get('weight') != 100
                    or not response.get('updateDate')):
                return None
            flag = 'sfn_alias_routed_to_version'
        else:
            flag = 'sfn_alias_deleted'
    else:
        target = req.get('stateMachineVersionArn')
        match = _VERSION.fullmatch(target) if isinstance(target, str) else None
        if not match or match.group(1) != region or match.group(2) != account:
            return None
        flag = 'sfn_version_deleted'
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'states.amazonaws.com',
        'event.name': name, 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity.get('arn'), 'target.id': target,
        f'request.{flag}': True,
    }


def normalize_aws_stepfunctions_redrive(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource') != 'states.amazonaws.com'
            or record.get('eventName') != 'RedriveExecution'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('eventCategory') != 'Management'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not False
            or record.get('errorCode') or record.get('errorMessage')):
        return None
    req = record.get('requestParameters')
    response = record.get('responseElements')
    if not isinstance(req, Mapping) or not isinstance(response, Mapping):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    target = req.get('executionArn')
    match = _EXECUTION.fullmatch(target) if isinstance(target, str) else None
    if (not match or not isinstance(account, str) or match.group(1) != region
            or match.group(2) != account or not response.get('redriveDate')):
        return None
    identity = record.get('userIdentity')
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        'cloud.provider': 'aws', 'event.source': 'states.amazonaws.com',
        'event.name': 'RedriveExecution', 'event.outcome': 'success',
        'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
        'account.id': account, 'actor.id': identity.get('arn'), 'target.id': target,
        'request.sfn_execution_redriven': True,
    }
