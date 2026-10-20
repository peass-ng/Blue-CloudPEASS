"""Synthetic derivatives of owned CodePipeline read and custom-action routes."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT='999999999999';PIPELINE='synthetic-pipeline';PROVIDER='SyntheticGate';JOB='11111111-1111-4111-8111-111111111111'
ACTOR=f'arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-reader/run'
NAMES={'GetPipeline','GetPipelineExecution','ListActionExecutions','PollForJobs','GetJobDetails'}


def event(name,request,minute):
 return {'eventSource':'codepipeline.amazonaws.com','eventName':name,
         'eventCategory':'Management','eventType':'AwsApiCall','managementEvent':True,
         'readOnly':name!='PollForJobs','recipientAccountId':ACCOUNT,'awsRegion':'us-east-1',
         'eventID':f'22222222-2222-4222-8222-{minute+1:012d}',
         'eventTime':(datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(minutes=minute)).isoformat(),
         'userIdentity':{'accountId':ACCOUNT,'arn':ACTOR},'requestParameters':request,
         'responseElements':None}


def records():
 return [
  event('GetPipeline',{'name':PIPELINE},0),
  event('GetPipelineExecution',{'pipelineName':PIPELINE,'pipelineExecutionId':JOB},1),
  event('ListActionExecutions',{'pipelineName':PIPELINE,'filter':{'pipelineExecutionId':JOB}},2),
  event('PollForJobs',{'actionTypeId':{'category':'Test','owner':'Custom','provider':PROVIDER,'version':'1'},'maxBatchSize':1},3),
  event('GetJobDetails',{'jobId':JOB},4),
 ]


def rules():
 return [r for r in load_rules(product='aws') if isinstance(r.selection.get('event.name'),str)
         and r.selection['event.name'] in NAMES and r.selection.get('event.source')=='codepipeline.amazonaws.com']


def test_five_read_routes_match_without_claiming_returned_values():
 found=detect_aws_events(records(),rules())
 assert len(found)==5
 assert {x.rule_id for x in found}=={r.id for r in rules()}
 text=str(found)
 assert JOB not in text
 assert PROVIDER not in text


def test_read_routes_reject_denials_and_wrong_request_shapes():
 for index,change in (
  (0,{'errorCode':'AccessDeniedException'}),
  (1,{'requestParameters':{'pipelineName':PIPELINE,'pipelineExecutionId':'bad'}}),
  (2,{'requestParameters':{'pipelineName':'bad/name'}}),
  (3,{'requestParameters':{'actionTypeId':{'category':'Test','owner':'AWS','provider':PROVIDER,'version':'1'}}}),
  (4,{'readOnly':False}),
 ):
  changed=deepcopy(records()[index]);changed.update(change)
  assert not detect_aws_events([changed],rules()),index
