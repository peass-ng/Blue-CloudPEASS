"""EventBridge connection and destination control plane signals."""
from copy import deepcopy
from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT='222233334444'
REGION='us-east-1'
CONN='example-conn-61a28a60e5'
DEST='example-dest-61a28a60e5'
CONN_ARN=f'arn:aws:events:{REGION}:{ACCOUNT}:connection/{CONN}/f1152baf-f71c-476d-9055-6052e3db649d'
DEST_ARN=f'arn:aws:events:{REGION}:{ACCOUNT}:api-destination/{DEST}/ef622688-a61c-4ab8-9f3a-b4f56f44fe91'
RULES=[Rule(id=key,title=key,level='low',description=key,technique_id=key,product='aws',selection={
    'event.source':'events.amazonaws.com','event.outcome':'success',flag:True}) for key,flag in (
    ('destination','request.eventbridge_api_destination_endpoint_updated'),
    ('credential','request.eventbridge_connection_credential_updated'),
    ('deauth','request.eventbridge_connection_deauthorization_started'))]


def event(name,request,response):
    return {'eventSource':'events.amazonaws.com','eventName':name,'eventCategory':'Management',
            'eventType':'AwsApiCall','managementEvent':True,'readOnly':False,'recipientAccountId':ACCOUNT,
            'awsRegion':REGION,'requestParameters':request,'responseElements':response,'eventID':'lab-event'}


def hits(record):
    return [x.technique_id for x in detect_aws_events([record],RULES)]


def test_update_endpoint_live_shape_and_negative_controls():
    record=event('UpdateApiDestination',{'name':DEST,'invocationEndpoint':'https://example.net/example-lab'},
                 {'apiDestinationArn':DEST_ARN,'apiDestinationState':'ACTIVE'})
    assert hits(record)==['destination']
    for variant in ('error','missing_endpoint','inactive','wrong_arn','read_only'):
        item=deepcopy(record)
        if variant=='error':item['errorCode']='AccessDeniedException'
        if variant=='missing_endpoint':item['requestParameters'].pop('invocationEndpoint')
        if variant=='inactive':item['responseElements']['apiDestinationState']='INACTIVE'
        if variant=='wrong_arn':item['responseElements']['apiDestinationArn']=CONN_ARN
        if variant=='read_only':item['readOnly']=True
        assert hits(item)==[],variant


def test_update_credential_live_shape_and_negative_controls():
    record=event('UpdateConnection',{'name':CONN,'authorizationType':'API_KEY',
                 'authParameters':{'apiKeyAuthParameters':{'apiKeyName':'x-example-lab','apiKeyValue':'HIDDEN_DUE_TO_SECURITY_REASONS'}}},
                 {'connectionArn':CONN_ARN,'connectionState':'AUTHORIZED'})
    assert hits(record)==['credential']
    for variant in ('error','description_only','bad_arn','state'):
        item=deepcopy(record)
        if variant=='error':item['errorCode']='ValidationException'
        if variant=='description_only':item['requestParameters'].pop('authParameters')
        if variant=='bad_arn':item['responseElements']['connectionArn']=DEST_ARN
        if variant=='state':item['responseElements']['connectionState']='DEAUTHORIZED'
        assert hits(item)==[],variant


def test_deauthorize_live_shape_and_negative_controls():
    record=event('DeauthorizeConnection',{'name':CONN},
                 {'connectionArn':CONN_ARN,'connectionState':'DEAUTHORIZING'})
    assert hits(record)==['deauth']
    for variant in ('error','wrong_state','wrong_name','read_only'):
        item=deepcopy(record)
        if variant=='error':item['errorCode']='ResourceNotFoundException'
        if variant=='wrong_state':item['responseElements']['connectionState']='AUTHORIZED'
        if variant=='wrong_name':item['requestParameters']['name']='other'
        if variant=='read_only':item['readOnly']=True
        assert hits(item)==[],variant
