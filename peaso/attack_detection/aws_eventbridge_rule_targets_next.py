"""Accepted EventBridge catch-all rules, external targets, and target removal."""
from __future__ import annotations
import json
import re
from collections.abc import Mapping
from typing import Any


def normalize_aws_eventbridge_rule_targets(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'events.amazonaws.com' or name not in {'PutRule','PutTargets','RemoveTargets','StartReplay'}
            or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    req, resp = record.get('requestParameters'), record.get('responseElements')
    if not isinstance(req, Mapping) or not isinstance(resp, Mapping): return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account,str) or re.fullmatch(r'\d{12}',account) is None or not isinstance(region,str): return None
    if name == 'StartReplay':
        replay = req.get('replayName')
        if not isinstance(replay,str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}',replay): return None
        source = req.get('eventSourceArn')
        destination = req.get('destination')
        expected = f'arn:aws:events:{region}:{account}:replay/{replay}'
        source_ok = isinstance(source,str) and re.fullmatch(
            rf'arn:aws:events:{re.escape(region)}:{account}:archive/[A-Za-z0-9._-]+',source) is not None
        dest_ok = (isinstance(destination,Mapping) and isinstance(destination.get('arn'),str)
                   and re.fullmatch(rf'arn:aws:events:{re.escape(region)}:{account}:event-bus/[A-Za-z0-9._/-]+',destination['arn']) is not None)
        accepted = (not record.get('errorCode') and not record.get('errorMessage')
                    and source_ok and dest_ok and resp.get('replayArn')==expected
                    and resp.get('state') in {'STARTING','RUNNING','COMPLETED'})
        identity=record.get('userIdentity')
        identity=identity if isinstance(identity,Mapping) else {}
        return {'cloud.provider':'aws','event.source':'events.amazonaws.com','event.name':name,
                'event.outcome':'success' if accepted else 'failure','event.id':record.get('eventID'),
                'event.time':record.get('eventTime'),'account.id':account,'actor.id':identity.get('arn'),
                'target.id':expected,'request.eventbridge_replay_started':accepted}
    rule = req.get('name' if name == 'PutRule' else 'rule')
    bus = req.get('eventBusName','default')
    if not isinstance(rule,str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}',rule): return None
    if not isinstance(bus,str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,256}',bus): return None
    arn = f'arn:aws:events:{region}:{account}:rule/' + ('' if bus=='default' else bus+'/') + rule
    failed = bool(record.get('errorCode') or record.get('errorMessage') or resp.get('errorCode') or resp.get('errorMessage'))
    count = resp.get('failedEntryCount')
    accepted = not failed and (name=='PutRule' and resp.get('ruleArn')==arn or name!='PutRule' and count==0 and resp.get('failedEntries')==[])
    catchall = False
    if name=='PutRule' and accepted and isinstance(req.get('eventPattern'),str):
        try: pattern=json.loads(req['eventPattern'])
        except (ValueError,TypeError): pattern=None
        catchall = isinstance(pattern,dict) and set(pattern)=={'source'} and pattern['source']==[{'prefix':''}]
    external_target = api_destination_target = False
    if name=='PutTargets' and accepted and isinstance(req.get('targets'),list):
        for target in req['targets']:
            if not isinstance(target,Mapping) or not isinstance(target.get('id'),str): continue
            target_arn=target.get('arn')
            if not isinstance(target_arn,str): continue
            parts=target_arn.split(':',5)
            if (len(parts)==6 and parts[0]=='arn' and parts[1]=='aws' and parts[2] in {'sqs','sns','lambda','events'}
                    and parts[3]==region and re.fullmatch(r'\d{12}',parts[4]) and parts[4]!=account):
                external_target=True
            role_arn=target.get('roleArn')
            if (re.fullmatch(rf'arn:aws:events:{re.escape(region)}:{account}:api-destination/[A-Za-z0-9._-]+/[0-9a-f-]{{36}}',target_arn)
                    and isinstance(role_arn,str)
                    and role_arn.startswith(f'arn:aws:iam::{account}:role/')
                    and role_arn.split(':role/',1)[1]):
                api_destination_target=True
    removed = (name=='RemoveTargets' and accepted and isinstance(req.get('ids'),list)
               and bool(req['ids']) and all(isinstance(x,str) and bool(x) for x in req['ids']))
    identity=record.get('userIdentity')
    identity=identity if isinstance(identity,Mapping) else {}
    return {'cloud.provider':'aws','event.source':'events.amazonaws.com','event.name':name,
            'event.outcome':'success' if accepted else 'failure','event.id':record.get('eventID'),
            'event.time':record.get('eventTime'),'account.id':account,'actor.id':identity.get('arn'),
            'target.id':arn,'request.eventbridge_catchall_rule':catchall,
            'request.eventbridge_external_target':external_target,
            'request.eventbridge_api_destination_target':api_destination_target,
            'request.eventbridge_targets_removed':removed}
