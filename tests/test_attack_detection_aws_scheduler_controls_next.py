"""EventBridge Scheduler accepted disable, deletion, and universal target changes."""
from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT='222233334444'
NAME='example-scheduler-21dc5f6c85'
ARN=f'arn:aws:scheduler:us-east-1:{ACCOUNT}:schedule/default/{NAME}'
ROLE=f'arn:aws:iam::{ACCOUNT}:role/example-scheduler-role-21dc5f6c85'
RULES=[
    Rule(id='disabled',title='Schedule disabled',level='medium',description='disabled',
         technique_id='aws-scheduler-schedule-disabled',product='aws',selection={
             'event.source':'scheduler.amazonaws.com','event.outcome':'success','request.scheduler_disabled':True}),
    Rule(id='deleted',title='Schedule deleted',level='low',description='deleted',
         technique_id='aws-scheduler-schedule-deleted',product='aws',selection={
             'event.source':'scheduler.amazonaws.com','event.outcome':'success','request.scheduler_deleted':True}),
    Rule(id='universal',title='Universal target configured',level='medium',description='universal',
         technique_id='aws-scheduler-universal-target-configured',product='aws',selection={
             'event.source':'scheduler.amazonaws.com','event.outcome':'success','request.scheduler_universal_target':True}),
]


def event(operation: str, request: dict, response: dict | None) -> dict:
    return {'eventSource':'scheduler.amazonaws.com','eventName':operation,'eventCategory':'Management',
            'eventType':'AwsApiCall','managementEvent':True,'readOnly':False,'recipientAccountId':ACCOUNT,
            'awsRegion':'us-east-1','requestParameters':request,'responseElements':response}


def hits(record: dict) -> list[str]:
    return [hit.technique_id for hit in detect_aws_events([record],RULES)]


def test_schedule_disable_and_restore() -> None:
    request={'name':NAME,'scheduleExpression':'at(2026-10-20T12:00:00)','state':'DISABLED',
             'target':{'arn':f'arn:aws:sqs:us-east-1:{ACCOUNT}:queue','roleArn':ROLE},
             'flexibleTimeWindow':{'mode':'OFF'}}
    original=event('UpdateSchedule',request,{'scheduleArn':ARN})
    assert hits(original)==['aws-scheduler-schedule-disabled']
    for variant in ('enabled','failed','wrong_response','read_only'):
        item=deepcopy(original)
        if variant=='enabled':item['requestParameters']['state']='ENABLED'
        if variant=='failed':item['errorCode']='AccessDeniedException'
        if variant=='wrong_response':item['responseElements']['scheduleArn']+='-wrong'
        if variant=='read_only':item['readOnly']=True
        assert hits(item)==[],variant


def test_schedule_delete_requires_accepted_call() -> None:
    original=event('DeleteSchedule',{'name':NAME,'clientToken':'test-token'},None)
    assert hits(original)==['aws-scheduler-schedule-deleted']
    item=deepcopy(original);item['errorCode']='ResourceNotFoundException'
    assert hits(item)==[]


def test_universal_target_uses_same_account_role_and_valid_response() -> None:
    name='example-scheduler-universal-21dc5f6c85'
    arn=f'arn:aws:scheduler:us-east-1:{ACCOUNT}:schedule/default/{name}'
    request={'name':name,'scheduleExpression':'at(2026-10-20T12:00:00)','state':'DISABLED',
             'target':{'arn':'arn:aws:scheduler:::aws-sdk:sqs:sendMessage','roleArn':ROLE,
                       'input':'{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/..."}'},
             'flexibleTimeWindow':{'mode':'OFF'}}
    original=event('CreateSchedule',request,{'scheduleArn':arn})
    assert hits(original)==['aws-scheduler-universal-target-configured']
    for variant in ('templated','foreign_role','failed','wrong_response'):
        item=deepcopy(original)
        if variant=='templated':item['requestParameters']['target']['arn']=f'arn:aws:sqs:us-east-1:{ACCOUNT}:queue'
        if variant=='foreign_role':item['requestParameters']['target']['roleArn']=ROLE.replace(ACCOUNT,'999999999999')
        if variant=='failed':item['errorCode']='AccessDeniedException'
        if variant=='wrong_response':item['responseElements']['scheduleArn']+='-wrong'
        assert hits(item)==[],variant
