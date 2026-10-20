"""Enhanced EventBridge bus control signals from accepted CloudTrail shapes."""
from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT='222233334444'
REGION='us-east-1'
BUS=f'arn:aws:events:{REGION}:{ACCOUNT}:event-busv2/example-v2-bus-22025424a4/20crf6jl9o4tmu8p4y9fjqjtm'
SUB=f'arn:aws:events:{REGION}:{ACCOUNT}:subscriber/example-v2-sub-22025424a4/d6dx063dyn5er8a5dst3g4eln'
RULES=[Rule(id=i,title=i,level='medium',description=i,technique_id=t,product='aws',selection={
    'event.source':'eventsv2.amazonaws.com','event.outcome':'success','request.'+i:True})
    for i,t in [
        ('eventsv2_backfill_subscriber','aws-eventsv2-backfill-subscriber'),
        ('eventsv2_universal_target_subscriber','aws-eventsv2-universal-target-subscriber'),
        ('eventsv2_subscriber_filter_cleared','aws-eventsv2-subscriber-filter-cleared'),
        ('eventsv2_subscriber_logs_off','aws-eventsv2-subscriber-logs-off'),
        ('eventsv2_subscriber_paused','aws-eventsv2-subscriber-paused'),
        ('eventsv2_resume_latest_requested','aws-eventsv2-resume-latest-requested'),
        ('eventsv2_retention_one_day','aws-eventsv2-one-day-retention')]]


def base(operation: str, request: dict, response: dict) -> dict:
    return {'eventSource':'eventsv2.amazonaws.com','eventName':operation,'eventCategory':'Management',
            'eventType':'AwsApiCall','managementEvent':True,'readOnly':False,'awsRegion':REGION,
            'recipientAccountId':ACCOUNT,'requestParameters':request,'responseElements':response}


def hits(record: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([record],RULES)]


def test_backfill_subscriber_and_latest_negative() -> None:
    name='example-v2-sub-22025424a4'
    record=base('CreateSubscriber',{'name':name,'eventBusArn':BUS,'startingPosition':'POINT_IN_TIME',
        'pointInTimeConfiguration':{'pointType':'HORIZON'},'state':'RUNNING'},
        {'subscriberArn':SUB,'name':name,'eventBusArn':BUS,'startingPosition':'POINT_IN_TIME','state':'RUNNING'})
    assert hits(record)==['aws-eventsv2-backfill-subscriber']
    for variant in ('latest','stopped','error','wrong_bus','wrong_sub'):
        item=deepcopy(record)
        if variant=='latest':item['requestParameters']['startingPosition']='LATEST'
        if variant=='stopped':item['requestParameters']['state']='STOPPED'
        if variant=='error':item['errorCode']='AccessDeniedException'
        if variant=='wrong_bus':item['responseElements']['eventBusArn']+='-other'
        if variant=='wrong_sub':item['responseElements']['subscriberArn']+='-other'
        assert hits(item)==[],variant


def test_pause_and_latest_resume_requests() -> None:
    paused=base('UpdateSubscriber',{'subscriberArn':SUB,'state':'STOPPED'},
        {'subscriberArn':SUB,'state':'STOPPED'})
    assert hits(paused)==['aws-eventsv2-subscriber-paused']
    resumed=base('UpdateSubscriber',{'subscriberArn':SUB,'state':'RUNNING','resumePosition':'LATEST'},
        {'subscriberArn':SUB,'state':'RUNNING'})
    assert hits(resumed)==['aws-eventsv2-resume-latest-requested']
    for variant in ('last_processed','error','wrong_response'):
        item=deepcopy(resumed)
        if variant=='last_processed':item['requestParameters']['resumePosition']='LAST_PROCESSED'
        if variant=='error':item['errorCode']='InvalidInputException'
        if variant=='wrong_response':item['responseElements']['subscriberArn']+='-other'
        assert hits(item)==[],variant


def test_one_day_bus_retention_and_controls() -> None:
    record=base('UpdateEventBus',{'eventBusArn':BUS,'storageConfiguration':{'retentionPeriodInDays':1}},
        {'eventBusArn':BUS,'storageConfiguration':{'retentionPeriodInDays':1},'state':'ACTIVE'})
    assert hits(record)==['aws-eventsv2-one-day-retention']
    for variant in ('two_days','error','wrong_response'):
        item=deepcopy(record)
        if variant=='two_days':item['requestParameters']['storageConfiguration']['retentionPeriodInDays']=2
        if variant=='error':item['errorCode']='InvalidInputException'
        if variant=='wrong_response':item['responseElements']['eventBusArn']+='-other'
        assert hits(item)==[],variant


def test_universal_target_subscriber_from_live_cloudtrail_shape() -> None:
    name='example-v2-sub-22025424a4'
    record=base('CreateSubscriber',{'name':name,'eventBusArn':BUS,'startingPosition':'LATEST',
        'invokeConfiguration':{
            'roleArn':f'arn:aws:iam::{ACCOUNT}:role/example-lab-role',
            'targetArn':'arn:aws:events:::aws-sdk:s3:putObject',
            'universalTargetParameters':'HIDDEN_DUE_TO_SECURITY_REASONS'},
        'batchConfiguration':{'maxBatchSize':1,'maxBatchWindowInSeconds':0},'state':'RUNNING'},
        {'subscriberArn':SUB,'name':name,'eventBusArn':BUS,'startingPosition':'LATEST','state':'RUNNING'})
    assert hits(record)==['aws-eventsv2-universal-target-subscriber']
    for variant in ('error','queue_target','foreign_role','missing_input','stopped','wrong_subscriber'):
        item=deepcopy(record)
        if variant=='error':item['errorCode']='AccessDeniedException'
        if variant=='queue_target':item['requestParameters']['invokeConfiguration']['targetArn']=f'arn:aws:sqs:{REGION}:{ACCOUNT}:queue'
        if variant=='foreign_role':item['requestParameters']['invokeConfiguration']['roleArn']=item['requestParameters']['invokeConfiguration']['roleArn'].replace(ACCOUNT,'999999999999')
        if variant=='missing_input':item['requestParameters']['invokeConfiguration'].pop('universalTargetParameters')
        if variant=='stopped':item['responseElements']['state']='STOPPED'
        if variant=='wrong_subscriber':item['responseElements']['subscriberArn']+='-other'
        assert hits(item)==[],variant


def test_filter_clear_and_log_off_from_live_cloudtrail_shape() -> None:
    record=base('UpdateSubscriber',{'subscriberArn':SUB,'filterConfiguration':{},
        'logConfiguration':{'level':'OFF','includePayload':'ON_ERROR_ONLY'}},
        {'subscriberArn':SUB,'eventBusArn':BUS,'state':'RUNNING'})
    assert hits(record)==['aws-eventsv2-subscriber-filter-cleared','aws-eventsv2-subscriber-logs-off']
    missing_filter=deepcopy(record)
    missing_filter['requestParameters'].pop('filterConfiguration')
    assert hits(missing_filter)==['aws-eventsv2-subscriber-logs-off']
    missing_logs=deepcopy(record)
    missing_logs['requestParameters'].pop('logConfiguration')
    assert hits(missing_logs)==['aws-eventsv2-subscriber-filter-cleared']
    for variant in ('error','wrong_arn','read_only','nonempty_filter_and_info'):
        item=deepcopy(record)
        if variant=='error':item['errorCode']='AccessDeniedException'
        if variant=='wrong_arn':item['responseElements']['subscriberArn']+='-other'
        if variant=='read_only':item['readOnly']=True
        if variant=='nonempty_filter_and_info':
            item['requestParameters']['filterConfiguration']={'filters':[{'scope':'DATA','pattern':'{}'}]}
            item['requestParameters']['logConfiguration']['level']='INFO'
        assert hits(item)==[],variant
