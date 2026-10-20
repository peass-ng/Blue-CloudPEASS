"""Synthetic derivatives of an owned CodePipeline update and custom-gate lab."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT='999999999999';REGION='us-east-1';PIPELINE='synthetic-pipeline';PROJECT='synthetic-project'
PROJECT_ARN=f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/{PROJECT}'
ACTOR=f'arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-operator/run'
WORKER=f'arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-worker/run'
REPORTER=f'arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-reporter/run'
UUID='11111111-1111-4111-8111-111111111111';OLDER='22222222-2222-4222-8222-222222222222';NEW='33333333-3333-4333-8333-333333333333'
BUCKET='synthetic-source-bucket';KEY='source/synthetic.zip'
IDS={r.id for r in load_rules(product='aws') if isinstance(r.selection.get('event.name'),str) and r.selection['event.name'] in {
 'CodePipelineProjectMutationExecuted','OverrideStageCondition','RollbackStage',
 'CodePipelineS3SourceOverwriteBeforeStart','CodePipelineCustomJobCrossActorSuccess'}}


def event(name,source,request,response,minute,actor=ACTOR,category='Management'):
 return {'eventSource':source,'eventName':name,'eventCategory':category,'eventType':'AwsApiCall',
         'managementEvent':category=='Management','readOnly':False,'recipientAccountId':ACCOUNT,
         'awsRegion':REGION,'eventID':f'44444444-4444-4444-8444-{minute+1:012d}',
         'eventTime':(datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(minutes=minute)).isoformat(),
         'userIdentity':{'accountId':ACCOUNT,'arn':actor},'requestParameters':request,'responseElements':response}


def pipeline():
 return {'name':PIPELINE,'stages':[
  {'name':'Source','actions':[{'actionTypeId':{'category':'Source','provider':'S3'},
    'configuration':{'S3Bucket':BUCKET,'S3ObjectKey':KEY}}]},
  {'name':'Build','actions':[{'actionTypeId':{'category':'Build','provider':'CodeBuild'},
    'configuration':{'ProjectName':PROJECT,'EnvironmentVariables':'synthetic-only'}}]}]}


def records():
 p=pipeline()
 return [
  event('UpdateProject','codebuild.amazonaws.com',{'name':PROJECT_ARN,'source':{'type':'CODEPIPELINE','buildspec':'HIDDEN_DUE_TO_SECURITY_REASONS'}},
        {'project':{'name':PROJECT,'arn':PROJECT_ARN,'source':{'type':'CODEPIPELINE','buildspec':'HIDDEN_DUE_TO_SECURITY_REASONS'}}},0),
  event('UpdatePipeline','codepipeline.amazonaws.com',{'pipeline':p},{'pipeline':p},1),
  event('StartPipelineExecution','codepipeline.amazonaws.com',{'name':PIPELINE},{'pipelineExecutionId':UUID},2),
  event('PutObject','s3.amazonaws.com',{'bucketName':BUCKET,'key':KEY},{},3,category='Data'),
  event('StartPipelineExecution','codepipeline.amazonaws.com',{'name':PIPELINE},{'pipelineExecutionId':OLDER},4),
  event('OverrideStageCondition','codepipeline.amazonaws.com',{'pipelineName':PIPELINE,'stageName':'Build',
       'pipelineExecutionId':OLDER,'conditionType':'BEFORE_ENTRY'},None,5),
  event('RollbackStage','codepipeline.amazonaws.com',{'pipelineName':PIPELINE,'stageName':'Build',
       'targetPipelineExecutionId':OLDER},{'pipelineExecutionId':NEW},6),
  event('AcknowledgeJob','codepipeline.amazonaws.com',{'jobId':UUID,'nonce':'synthetic-private-nonce'},
       {'status':'InProgress'},7,actor=WORKER),
  event('PutJobSuccessResult','codepipeline.amazonaws.com',{'jobId':UUID},None,8,actor=REPORTER),
 ]


def rules():
 return [r for r in load_rules(product='aws') if r.id in IDS]


def test_five_codepipeline_routes_match_without_sensitive_evidence():
 found=detect_aws_events(records(),rules())
 assert {x.rule_id for x in found}==IDS
 assert len(found)==5
 assert 'synthetic-private-nonce' not in str(found)
 assert KEY not in str(found)
 assert 'HIDDEN_DUE_TO_SECURITY_REASONS' not in str(found)


def test_codepipeline_routes_reject_denials_wrong_targets_and_same_actor_job():
 for index,change in (
  (0,{'errorCode':'AccessDeniedException'}),
  (1,{'requestParameters':{'pipeline':{'name':PIPELINE,'stages':[]}}}),
  (3,{'requestParameters':{'bucketName':BUCKET,'key':'other.zip'}}),
  (5,{'errorCode':'ConditionNotOverridableException'}),
  (6,{'responseElements':{'pipelineExecutionId':OLDER}}),
  (8,{'userIdentity':{'accountId':ACCOUNT,'arn':WORKER}}),
 ):
  changed=deepcopy(records());changed[index].update(change)
  got={x.rule_id for x in detect_aws_events(changed,rules())}
  assert len(got)<5,(index,got)
