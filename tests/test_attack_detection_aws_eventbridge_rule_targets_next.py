"""EventBridge rule/target/replay facts from accepted CloudTrail shapes."""
from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = '222233334444'
REGION = 'us-east-1'
BUS = 'example-next-bus-82e4dfadc9'
RULE_NAME = 'example-next-rule-82e4dfadc9'
RULE_ARN = f'arn:aws:events:{REGION}:{ACCOUNT}:rule/{BUS}/{RULE_NAME}'
RULES = [
    Rule(id='catchall',title='Catch-all rule',level='medium',description='catchall',
         technique_id='aws-eventbridge-catchall-rule',product='aws',selection={
             'event.source':'events.amazonaws.com','event.outcome':'success','request.eventbridge_catchall_rule':True}),
    Rule(id='removed',title='Targets removed',level='low',description='removed',
         technique_id='aws-eventbridge-remove-targets',product='aws',selection={
             'event.source':'events.amazonaws.com','event.outcome':'success','request.eventbridge_targets_removed':True}),
    Rule(id='replay',title='Replay started',level='low',description='replay',
         technique_id='aws-eventbridge-start-replay',product='aws',selection={
             'event.source':'events.amazonaws.com','event.outcome':'success','request.eventbridge_replay_started':True}),
    Rule(id='http',title='API destination target',level='medium',description='http',
         technique_id='aws-eventbridge-api-destination-target-configured',product='aws',selection={
             'event.source':'events.amazonaws.com','event.outcome':'success','request.eventbridge_api_destination_target':True}),
]


def base(name: str, request: dict, response: dict) -> dict:
    return {'eventSource':'events.amazonaws.com','eventName':name,'eventCategory':'Management',
            'eventType':'AwsApiCall','managementEvent':True,'readOnly':False,
            'recipientAccountId':ACCOUNT,'awsRegion':REGION,'requestParameters':request,
            'responseElements':response,'eventID':'live-shape'}


def hits(event: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([event],RULES)]


def test_catchall_rule_matches_live_shape_and_rejects_narrowed_or_failed() -> None:
    event=base('PutRule',{'name':RULE_NAME,'eventBusName':BUS,'state':'ENABLED',
        'eventPattern':json.dumps({'source':[{'prefix':''}]})},{'ruleArn':RULE_ARN})
    assert hits(event)==['aws-eventbridge-catchall-rule']
    for variant in ('narrow','extra_filter','error','wrong_arn','read_only'):
        item=deepcopy(event)
        if variant=='narrow':item['requestParameters']['eventPattern']=json.dumps({'source':['peasso.baseline']})
        if variant=='extra_filter':item['requestParameters']['eventPattern']=json.dumps({'source':[{'prefix':''}],'detail-type':['Canary']})
        if variant=='error':item['errorCode']='AccessDeniedException'
        if variant=='wrong_arn':item['responseElements']['ruleArn']+='-wrong'
        if variant=='read_only':item['readOnly']=True
        assert hits(item)==[],variant


def test_target_removal_requires_all_entries_accepted() -> None:
    event=base('RemoveTargets',{'rule':RULE_NAME,'eventBusName':BUS,'ids':['primary'],'force':False},
               {'failedEntryCount':0,'failedEntries':[]})
    assert hits(event)==['aws-eventbridge-remove-targets']
    for variant in ('partial','empty','error'):
        item=deepcopy(event)
        if variant=='partial':item['responseElements']['failedEntryCount']=1
        if variant=='empty':item['requestParameters']['ids']=[]
        if variant=='error':item['errorCode']='ResourceNotFoundException'
        assert hits(item)==[],variant


def test_replay_requires_matching_archive_bus_and_response() -> None:
    name='cp-xreplay-final-20260911-replay-final2'
    event=base('StartReplay',{'replayName':name,'eventSourceArn':f'arn:aws:events:{REGION}:{ACCOUNT}:archive/archive',
        'eventStartTime':'2026-09-11T09:39:28Z','eventEndTime':'2026-09-11T09:54:29Z',
        'destination':{'arn':f'arn:aws:events:{REGION}:{ACCOUNT}:event-bus/bus'}},
        {'replayArn':f'arn:aws:events:{REGION}:{ACCOUNT}:replay/{name}','state':'STARTING'})
    assert hits(event)==['aws-eventbridge-start-replay']
    for variant in ('error','foreign_archive','foreign_bus','wrong_arn'):
        item=deepcopy(event)
        if variant=='error':item['errorCode']='AccessDeniedException'
        if variant=='foreign_archive':item['requestParameters']['eventSourceArn']=item['requestParameters']['eventSourceArn'].replace(ACCOUNT,'999999999999')
        if variant=='foreign_bus':item['requestParameters']['destination']['arn']=item['requestParameters']['destination']['arn'].replace(ACCOUNT,'999999999999')
        if variant=='wrong_arn':item['responseElements']['replayArn']+='-wrong'
        assert hits(item)==[],variant


def test_api_destination_target_from_live_cloudtrail_shape() -> None:
    destination=f'arn:aws:events:{REGION}:{ACCOUNT}:api-destination/example-http-dest/6c0288a7-b063-4d95-bdae-e9e43a139a2b'
    role=f'arn:aws:iam::{ACCOUNT}:role/example-http-erole'
    record=base('PutTargets',{'rule':RULE_NAME,'eventBusName':BUS,'targets':[
        {'id':'baseline','arn':f'arn:aws:sqs:{REGION}:{ACCOUNT}:example-queue'},
        {'id':'http-copy','arn':destination,'roleArn':role}]},
        {'failedEntryCount':0,'failedEntries':[]})
    assert hits(record)==['aws-eventbridge-api-destination-target-configured']
    for variant in ('failed_entries','missing_role','foreign_role','ordinary_target','read_only','error'):
        item=deepcopy(record)
        if variant=='failed_entries':item['responseElements']['failedEntryCount']=1
        if variant=='missing_role':item['requestParameters']['targets'][1].pop('roleArn')
        if variant=='foreign_role':item['requestParameters']['targets'][1]['roleArn']=role.replace(ACCOUNT,'999999999999')
        if variant=='ordinary_target':item['requestParameters']['targets'][1]['arn']=f'arn:aws:sqs:{REGION}:{ACCOUNT}:example-copy'
        if variant=='read_only':item['readOnly']=True
        if variant=='error':item['errorCode']='AccessDeniedException'
        assert hits(item)==[],variant
