"""Accepted enhanced EventBridge bus replay, pause, skip, and retention requests."""
from __future__ import annotations
import re
from collections.abc import Mapping
from typing import Any


_BUS=re.compile(r'arn:aws:events:([a-z0-9-]+):(\d{12}):event-busv2/([A-Za-z0-9._-]+)/([a-z0-9]{25})\Z')
_SUB=re.compile(r'arn:aws:events:([a-z0-9-]+):(\d{12}):subscriber/([A-Za-z0-9._-]+)/([a-z0-9]{25})\Z')


def normalize_aws_eventsv2_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name=record.get('eventName')
    if (record.get('eventSource')!='eventsv2.amazonaws.com'
            or name not in {'CreateSubscriber','UpdateSubscriber','UpdateEventBus'}
            or record.get('eventCategory')!='Management' or record.get('eventType')!='AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    req,resp=record.get('requestParameters'),record.get('responseElements')
    if not isinstance(req,Mapping) or not isinstance(resp,Mapping):return None
    account,region=record.get('recipientAccountId'),record.get('awsRegion')
    if not isinstance(account,str) or re.fullmatch(r'\d{12}',account) is None or not isinstance(region,str):return None
    failed=bool(record.get('errorCode') or record.get('errorMessage'))
    backfill=paused=skip=short_retention=universal_target=filter_cleared=logs_off=False
    target=None
    if name=='CreateSubscriber':
        bus=req.get('eventBusArn');subname=req.get('name');sub=resp.get('subscriberArn')
        b=_BUS.fullmatch(bus) if isinstance(bus,str) else None
        m=_SUB.fullmatch(sub) if isinstance(sub,str) else None
        if (not b or not m or b.group(1)!=region or b.group(2)!=account or m.group(1)!=region
                or m.group(2)!=account or not isinstance(subname,str) or m.group(3)!=subname):return None
        if resp.get('eventBusArn')!=bus or resp.get('name')!=subname:return None
        target=sub
        point=req.get('pointInTimeConfiguration')
        point=point if isinstance(point,Mapping) else {}
        backfill=(not failed and req.get('startingPosition')=='POINT_IN_TIME'
                  and point.get('pointType') in {'HORIZON','TIMESTAMP'}
                  and req.get('state','RUNNING')=='RUNNING'
                  and resp.get('startingPosition')=='POINT_IN_TIME' and resp.get('state')=='RUNNING')
        invoke=req.get('invokeConfiguration')
        invoke=invoke if isinstance(invoke,Mapping) else {}
        role=invoke.get('roleArn')
        action=invoke.get('targetArn')
        role_prefix=f'arn:aws:iam::{account}:role/'
        universal_target=(not failed and isinstance(role,str)
                          and role.startswith(role_prefix) and bool(role[len(role_prefix):])
                          and isinstance(action,str)
                          and re.fullmatch(r'arn:aws:events:::aws-sdk:[a-z0-9-]+:[a-z][A-Za-z0-9]+',action) is not None
                          and bool(invoke.get('universalTargetParameters'))
                          and resp.get('state')=='RUNNING')
        accepted=not failed and resp.get('subscriberArn')==sub
    elif name=='UpdateSubscriber':
        sub=req.get('subscriberArn');m=_SUB.fullmatch(sub) if isinstance(sub,str) else None
        if not m or m.group(1)!=region or m.group(2)!=account or resp.get('subscriberArn')!=sub:return None
        target=sub
        accepted=not failed and resp.get('state') in {'RUNNING','STOPPED'}
        paused=accepted and req.get('state')=='STOPPED' and resp.get('state')=='STOPPED'
        skip=(accepted and req.get('state')=='RUNNING' and req.get('resumePosition')=='LATEST'
              and resp.get('state')=='RUNNING')
        filters=req.get('filterConfiguration')
        logging=req.get('logConfiguration')
        filter_cleared=accepted and isinstance(filters,Mapping) and not filters
        logs_off=accepted and isinstance(logging,Mapping) and logging.get('level')=='OFF'
    else:
        bus=req.get('eventBusArn');m=_BUS.fullmatch(bus) if isinstance(bus,str) else None
        if not m or m.group(1)!=region or m.group(2)!=account or resp.get('eventBusArn')!=bus:return None
        target=bus
        storage=req.get('storageConfiguration');response_storage=resp.get('storageConfiguration')
        accepted=not failed and resp.get('state') in {'ACTIVE','UPDATING'}
        short_retention=(accepted and isinstance(storage,Mapping) and isinstance(response_storage,Mapping)
                         and storage.get('retentionPeriodInDays')==1
                         and response_storage.get('retentionPeriodInDays')==1)
    identity=record.get('userIdentity')
    identity=identity if isinstance(identity,Mapping) else {}
    return {'cloud.provider':'aws','event.source':'eventsv2.amazonaws.com','event.name':name,
            'event.outcome':'success' if accepted else 'failure','event.id':record.get('eventID'),
            'event.time':record.get('eventTime'),'account.id':account,'actor.id':identity.get('arn'),
            'target.id':target,'request.eventsv2_backfill_subscriber':backfill,
            'request.eventsv2_universal_target_subscriber':universal_target,
            'request.eventsv2_subscriber_paused':paused,
            'request.eventsv2_resume_latest_requested':skip,
            'request.eventsv2_subscriber_filter_cleared':filter_cleared,
            'request.eventsv2_subscriber_logs_off':logs_off,
            'request.eventsv2_retention_one_day':short_retention}
