"""StartPipe accepted response must identify the requested pipe."""
from copy import deepcopy
from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT='222233334444'
NAME='example-pipe-97e5f9ce50'
ARN=f'arn:aws:pipes:us-east-1:{ACCOUNT}:pipe/{NAME}'
RULE=Rule(id='started',title='Pipe started',level='low',description='started',
          technique_id='aws-pipes-stopped-pipe-started',product='aws',selection={
              'event.source':'pipes.amazonaws.com','event.outcome':'success',
              'request.pipes_stopped_pipe_started':True})


def hits(event: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([event],[RULE])]


def test_accepted_start_pipe_and_negative_variants() -> None:
    event={'eventSource':'pipes.amazonaws.com','eventName':'StartPipe',
        'eventCategory':'Management','eventType':'AwsApiCall','managementEvent':True,'readOnly':False,
        'awsRegion':'us-east-1','recipientAccountId':ACCOUNT,'requestParameters':{'Name':NAME},
        'responseElements':{'Name':NAME,'Arn':ARN,'DesiredState':'RUNNING','CurrentState':'STARTING'}}
    assert hits(event)==[RULE.technique_id]
    for variant in ('error','wrong_arn','stopped','wrong_name','read_only'):
        item=deepcopy(event)
        if variant=='error':item['errorCode']='AccessDeniedException'
        if variant=='wrong_arn':item['responseElements']['Arn']+='-wrong'
        if variant=='stopped':item['responseElements']['DesiredState']='STOPPED'
        if variant=='wrong_name':item['responseElements']['Name']+='-wrong'
        if variant=='read_only':item['readOnly']=True
        assert hits(item)==[],variant
