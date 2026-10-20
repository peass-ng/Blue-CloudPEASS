"""Synthetic derivatives of an owned Lightsail instance and bucket lab."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT='999999999999';INSTANCE='synthetic-instance';BUCKET='synthetic-bucket'
ACTOR=f'arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-actor/run'
NAMES={'GetInstanceAccessDetails','CreateBucketAccessKey','OpenInstancePublicPorts',
       'PutInstancePublicPorts','SetResourceAccessForBucket','UpdateBucket'}


def event(name,request,response,minute):
 return {'eventSource':'lightsail.amazonaws.com','eventName':name,
         'eventCategory':'Management','eventType':'AwsApiCall','managementEvent':True,
         'readOnly':name=='GetInstanceAccessDetails','recipientAccountId':ACCOUNT,'awsRegion':'us-east-1',
         'eventID':f'11111111-1111-4111-8111-{minute+1:012d}',
         'eventTime':(datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(minutes=minute)).isoformat(),
         'userIdentity':{'accountId':ACCOUNT,'arn':ACTOR},
         'requestParameters':request,'responseElements':response}


def operation(resource):
 return {'resourceName':resource,'status':'Succeeded'}


def records():
 return [
  event('GetInstanceAccessDetails',{'instanceName':INSTANCE,'protocol':'ssh'},None,0),
  event('CreateBucketAccessKey',{'bucketName':BUCKET},
        {'accessKey':{'accessKeyId':'synthetic-key','secretAccessKey':'synthetic-private-secret','status':'Active'}},1),
  event('OpenInstancePublicPorts',{'instanceName':INSTANCE,'portInfo':{'fromPort':65001,'toPort':65001,
       'protocol':'tcp','cidrs':['0.0.0.0/0']}},{'operation':operation(INSTANCE)},2),
  event('PutInstancePublicPorts',{'instanceName':INSTANCE,'portInfos':[{'fromPort':65002,'toPort':65002,
       'protocol':'tcp','cidrs':['0.0.0.0/0']}]},{'operation':operation(INSTANCE)},3),
  event('SetResourceAccessForBucket',{'resourceName':INSTANCE,'bucketName':BUCKET,'access':'allow'},
        {'operations':[operation(INSTANCE),operation(BUCKET)]},4),
  event('UpdateBucket',{'bucketName':BUCKET,'accessRules':{'getObject':'public','allowPublicOverrides':True}},
        {'bucket':{'name':BUCKET,'accessRules':{'getObject':'public','allowPublicOverrides':True}}},5),
 ]


def rules():
 return [r for r in load_rules(product='aws') if isinstance(r.selection.get('event.name'),str)
         and r.selection['event.name'] in NAMES and r.selection.get('event.source')=='lightsail.amazonaws.com']


def test_six_lightsail_routes_match_without_exposing_key_material():
 found=detect_aws_events(records(),rules())
 assert len(found)==6
 assert {x.rule_id for x in found}=={r.id for r in rules()}
 assert 'synthetic-private-secret' not in str(found)
 assert 'synthetic-key' not in str(found)


def test_lightsail_routes_reject_denials_private_ports_and_revocations():
 for index,change in (
  (0,{'errorCode':'AccessDeniedException'}),
  (1,{'responseElements':{'accessKey':{'status':'Inactive'}}}),
  (2,{'requestParameters':{'instanceName':INSTANCE,'portInfo':{'fromPort':65001,'toPort':65001,'protocol':'tcp','cidrs':['10.0.0.0/8']}}}),
  (3,{'responseElements':{'operation':{'resourceName':INSTANCE,'status':'Failed'}}}),
  (4,{'requestParameters':{'resourceName':INSTANCE,'bucketName':BUCKET,'access':'deny'}}),
  (5,{'requestParameters':{'bucketName':BUCKET,'accessRules':{'getObject':'private'}}}),
 ):
  changed=deepcopy(records()[index]);changed.update(change)
  assert not detect_aws_events([changed],rules()),index
