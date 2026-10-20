"""Accepted start of a previously stopped EventBridge Pipe."""
from __future__ import annotations
import re
from collections.abc import Mapping
from typing import Any


def normalize_aws_pipes_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource')!='pipes.amazonaws.com' or record.get('eventName')!='StartPipe'
            or record.get('eventCategory')!='Management' or record.get('eventType')!='AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    req,resp=record.get('requestParameters'),record.get('responseElements')
    if not isinstance(req,Mapping) or not isinstance(resp,Mapping):return None
    name=req.get('Name')
    account,region=record.get('recipientAccountId'),record.get('awsRegion')
    if (not isinstance(name,str) or re.fullmatch(r'[A-Za-z0-9._-]{1,64}',name) is None
            or not isinstance(account,str) or re.fullmatch(r'\d{12}',account) is None
            or not isinstance(region,str)):return None
    arn=f'arn:aws:pipes:{region}:{account}:pipe/{name}'
    accepted=(not record.get('errorCode') and not record.get('errorMessage')
              and resp.get('Name')==name and resp.get('Arn')==arn
              and resp.get('DesiredState')=='RUNNING'
              and resp.get('CurrentState') in {'STARTING','RUNNING'})
    identity=record.get('userIdentity')
    identity=identity if isinstance(identity,Mapping) else {}
    return {'cloud.provider':'aws','event.source':'pipes.amazonaws.com','event.name':'StartPipe',
            'event.outcome':'success' if accepted else 'failure','event.id':record.get('eventID'),
            'event.time':record.get('eventTime'),'account.id':account,'actor.id':identity.get('arn'),
            'target.id':arn,'request.pipes_stopped_pipe_started':accepted}
