"""Accepted EventBridge Scheduler disable, deletion, and universal target setup."""
from __future__ import annotations
import re
from collections.abc import Mapping
from typing import Any


def normalize_aws_scheduler_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    operation=record.get('eventName')
    if (record.get('eventSource')!='scheduler.amazonaws.com'
            or operation not in {'CreateSchedule','UpdateSchedule','DeleteSchedule'}
            or record.get('eventCategory')!='Management' or record.get('eventType')!='AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    request=record.get('requestParameters')
    if not isinstance(request,Mapping):return None
    account,region=record.get('recipientAccountId'),record.get('awsRegion')
    name,group=request.get('name'),request.get('groupName','default')
    if (not isinstance(account,str) or re.fullmatch(r'\d{12}',account) is None
            or not isinstance(region,str) or not isinstance(name,str)
            or re.fullmatch(r'[A-Za-z0-9._-]{1,64}',name) is None
            or not isinstance(group,str) or re.fullmatch(r'[A-Za-z0-9._-]{1,64}',group) is None):
        return None
    arn=f'arn:aws:scheduler:{region}:{account}:schedule/{group}/{name}'
    response=record.get('responseElements')
    error=bool(record.get('errorCode') or record.get('errorMessage'))
    if operation=='DeleteSchedule':
        accepted=not error and response in (None,{})
    else:
        accepted=not error and isinstance(response,Mapping) and response.get('scheduleArn')==arn
    target=request.get('target')
    universal=False
    if accepted and operation in {'CreateSchedule','UpdateSchedule'} and isinstance(target,Mapping):
        target_arn=target.get('arn');role_arn=target.get('roleArn')
        universal=(isinstance(target_arn,str) and re.fullmatch(
            r'arn:aws:scheduler:::aws-sdk:[a-z0-9-]+:[A-Za-z][A-Za-z0-9]*',target_arn) is not None
            and isinstance(role_arn,str) and re.fullmatch(
                rf'arn:aws:iam::{account}:role/[A-Za-z0-9+=,.@_/-]+',role_arn) is not None)
    identity=record.get('userIdentity')
    identity=identity if isinstance(identity,Mapping) else {}
    return {'cloud.provider':'aws','event.source':'scheduler.amazonaws.com','event.name':operation,
            'event.outcome':'success' if accepted else 'failure','event.id':record.get('eventID'),
            'event.time':record.get('eventTime'),'account.id':account,'actor.id':identity.get('arn'),
            'target.id':arn,'request.scheduler_disabled':accepted and operation=='UpdateSchedule' and request.get('state')=='DISABLED',
            'request.scheduler_deleted':accepted and operation=='DeleteSchedule',
            'request.scheduler_universal_target':universal}
