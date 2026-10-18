"""Regional native evidence and binary Shield alarm semantics through real checks."""
from __future__ import annotations

import json
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,aws_region_shield_native as native
from peaso.collectors.bulk_evidence import collect
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot

SCOPE=ACCOUNT+'/'+REGION
REGION_CHECK='aws_g6_cloudtrail_region_logging_trail_present'
SHIELD_CHECK='aws_shield_ddos_detected_alarm'
PROTECTION='12345678-1234-1234-1234-123456789012'
EIP=f'arn:aws:ec2:{REGION}:{ACCOUNT}:eip-allocation/eipalloc-1234abcd'


def region_decision(read,logging=True,home=REGION,multi=False):
    trail={'TrailARN':f'arn:aws:cloudtrail:{home}:{ACCOUNT}:trail/audit','AccountId':ACCOUNT,
           'HomeRegion':home,'IsMultiRegionTrail':multi,'Status':{'IsLogging':logging}}
    snap=make_snapshot('aws',[SCOPE],[{'type':'aws_region','scope':SCOPE,'status':read.status,'items':read.items},
        {'type':'cloudtrail_account_inventory','scope':ACCOUNT+'/global','account_id':ACCOUNT,'global':True,'status':'collected','items':[trail]}])
    return [f['status']for f in evaluate_snapshot(snap,checks=[REGION_CHECK])['findings']]


@pytest.mark.parametrize('mode,expected',[
 ('enabled','PASS'),('opted_in','PASS'),('disabled','NOT_APPLICABLE'),('no_logging','FAIL'),('wrong_trail_home','FAIL'),
 ('multiregion_trail','PASS'),('denied','UNKNOWN'),('empty','UNKNOWN'),('missing_region','UNKNOWN'),
 ('duplicate','UNKNOWN'),('foreign_partition','UNKNOWN'),('missing_optin','UNKNOWN'),('unknown_optin','UNKNOWN')])
def test_region_native_opt_in_and_real_trail_check(sdk,mode,expected):
    session,add=sdk;ec2=add('ec2')
    row={'RegionName':REGION,'OptInStatus':'not-opted-in'if mode=='disabled'else'opted-in'if mode=='opted_in'else'opt-in-not-required'}
    if mode=='missing_region':row['RegionName']='eu-west-1'
    if mode=='foreign_partition':row['RegionName']='cn-north-1'
    if mode=='missing_optin':row.pop('OptInStatus')
    if mode=='unknown_optin':row['OptInStatus']='future-unsupported-state'
    if mode=='denied':ec2.add_client_error('describe_regions','UnauthorizedOperation',http_status_code=403,expected_params={'AllRegions':True})
    else:ec2.add_response('describe_regions',{'Regions':[]if mode=='empty'else[row]*(2 if mode=='duplicate'else 1)}, {'AllRegions':True})
    read=native.aws_region(aws.Requests({'retry_attempts':1}),session,REGION,ACCOUNT)
    if expected=='UNKNOWN':
        assert read.status not in ('collected','empty') and not any(s in ('PASS','FAIL','NOT_APPLICABLE')for s in region_decision(read))
    else:
        assert read.status=='collected'
        assert region_decision(read,logging=mode!='no_logging',home='eu-west-1'if mode in ('wrong_trail_home','multiregion_trail')else REGION,multi=mode=='multiregion_trail')==[expected]
    ec2.assert_no_pending_responses()


def protection(arn=EIP,ident=PROTECTION):
    return {'Id':ident,'ResourceArn':arn,'ProtectionArn':f'arn:aws:shield::{ACCOUNT}:protection/{ident}','Name':'not-exported-private-name'}


def alarm(resource=EIP,**changes):
    return {'AlarmArn':f'arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:ddos','Namespace':'AWS/DDoSProtection',
            'MetricName':'DDoSDetected','Dimensions':[{'Name':'ResourceArn','Value':resource}],
            'Period':60,'EvaluationPeriods':1,'Threshold':1,'ComparisonOperator':'GreaterThanOrEqualToThreshold',
            'ActionsEnabled':True,'AlarmActions':[f'arn:aws:sns:{REGION}:{ACCOUNT}:ddos'],**changes}


def shield_decision(read,alarms=None):
    alarms=[alarm()]if alarms is None else alarms
    snap=make_snapshot('aws',[SCOPE],[{'type':'shield_protection_region','scope':SCOPE,'status':read.status,'items':read.items},
                                   {'type':'cloudwatch_alarm','scope':SCOPE,'status':'collected'if alarms else'empty','items':alarms}])
    return [f['status']for f in evaluate_snapshot(snap,checks=[SHIELD_CHECK])['findings']]


@pytest.mark.parametrize('mode,expected',[
 ('complete','PASS'),('empty','NOT_APPLICABLE'),('foreign_region','NOT_APPLICABLE'),('no_alarm','FAIL'),
 ('cloudfront','PASS'),('route53','PASS'),('elb','PASS'),
 ('denied','UNKNOWN'),('not_found','UNKNOWN'),('truncated','UNKNOWN'),('duplicate_id','UNKNOWN'),('duplicate_resource','UNKNOWN'),
 ('foreign_account','UNKNOWN'),('foreign_protection_owner','UNKNOWN'),('foreign_partition','UNKNOWN'),('global_accelerator','UNKNOWN')])
def test_shield_native_metric_region_and_real_alarm_check(sdk,mode,expected):
    session,add=sdk;shield=add('shield');item=protection()
    if mode=='foreign_region':item['ResourceArn']=EIP.replace(REGION,'eu-west-1')
    if mode=='foreign_account':item['ResourceArn']=EIP.replace(ACCOUNT,'999999999999')
    if mode=='foreign_protection_owner':item['ProtectionArn']=item['ProtectionArn'].replace(ACCOUNT,'999999999999')
    if mode=='foreign_partition':item['ResourceArn']=EIP.replace('arn:aws:','arn:aws-cn:')
    if mode=='cloudfront':item['ResourceArn']=f'arn:aws:cloudfront::{ACCOUNT}:distribution/EABC123'
    if mode=='route53':item['ResourceArn']='arn:aws:route53:::hostedzone/ZABC123'
    if mode=='global_accelerator':item['ResourceArn']=f'arn:aws:globalaccelerator::{ACCOUNT}:accelerator/{PROTECTION}'
    if mode=='elb':item['ResourceArn']=f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/test/123abc'
    rows=[]if mode=='empty'else[item]
    if mode=='duplicate_id':rows.append(protection(EIP.replace('1234abcd','ffffffff')))
    if mode=='duplicate_resource':rows.append(protection(ident=PROTECTION.replace('12345678-','22345678-',1)))
    if mode in ('denied','not_found'):
        shield.add_client_error('list_protections','AccessDeniedException'if mode=='denied'else'ResourceNotFoundException',http_status_code=403 if mode=='denied'else 400,expected_params={})
    else:shield.add_response('list_protections',{'Protections':rows,**({'NextToken':'next'}if mode=='truncated'else{})}, {})
    if mode=='not_found':shield.add_response('get_subscription_state',{'SubscriptionState':'ACTIVE'}, {})
    read=native.shield_protection_region(aws.Requests({'retry_attempts':1,**({'max_pages':1}if mode=='truncated'else{})}),session,REGION,ACCOUNT)
    if expected=='UNKNOWN':
        assert read.status not in ('collected','empty')
        assert not any(s in ('PASS','FAIL','NOT_APPLICABLE')for s in shield_decision(read))
    else:
        assert shield_decision(read,[]if mode=='no_alarm'else[alarm(item['ResourceArn'])])==[expected]
        assert 'not-exported-private-name'not in json.dumps(read.items)
    shield.assert_no_pending_responses()


@pytest.mark.parametrize('comparison,threshold,expected',[
 ('GreaterThanOrEqualToThreshold',1,'PASS'),('GreaterThanThreshold',0,'PASS'),('GreaterThanThreshold',0.5,'PASS'),
 ('GreaterThanOrEqualToThreshold',0.5,'PASS'),('GreaterThanThreshold',1,'FAIL'),('GreaterThanOrEqualToThreshold',2,'FAIL'),
 ('GreaterThanThreshold',-1,'FAIL'),('GreaterThanOrEqualToThreshold',0,'FAIL'),
 ('LessThanThreshold',1,'FAIL'),('LessThanOrEqualToThreshold',1,'FAIL'),('unsupported',0,'UNKNOWN'),(None,0,'UNKNOWN')])
def test_binary_ddos_alarm_must_breach_on_attack_not_quiet_state(comparison,threshold,expected):
    row=alarm(ComparisonOperator=comparison,Threshold=threshold)
    if comparison is None:row.pop('ComparisonOperator')
    read=aws.ReadResult([{'ResourceArn':EIP,'SourceRegion':REGION}])
    assert shield_decision(read,[row])==[expected]


@pytest.mark.parametrize('change',[
 {'ActionsEnabled':False},{'AlarmActions':[]},
 {'Dimensions':[{'Name':'ResourceArn','Value':EIP},{'Name':'ExtraNonexistentMetricDimension','Value':'invented'}]}])
def test_disabled_actions_or_wrong_dimensions_do_not_satisfy_shield_coverage(change):
    assert shield_decision(aws.ReadResult([{'ResourceArn':EIP,'SourceRegion':REGION}]),[alarm(**change)])==['FAIL']


def test_protections_parent_cache_reused_and_global_metric_region_filtered(sdk):
    session,add=sdk;shield=add('shield');item=protection(f'arn:aws:cloudfront::{ACCOUNT}:distribution/EABC123')
    shield.add_response('list_protections',{'Protections':[item]}, {})
    requests=aws.Requests({'retry_attempts':1})
    east=native.shield_protection_region(requests,session,REGION,ACCOUNT)
    west=native.shield_protection_region(requests,session,'eu-west-1',ACCOUNT)
    assert east.status=='collected'and east.items[0]['SourceRegion']=='us-east-1'
    assert west.status=='empty'and requests.calls==1 and requests.cache_hits==1
    shield.assert_no_pending_responses()


def test_native_region_registration_and_declared_iam_operations():
    from scripts.peaso_deploy_customer_policy import iam_action
    assert native.READ_ACTIONS<=aws.READ_ACTIONS
    assert {iam_action(*pair)for pair in native.READ_ACTIONS}=={'ec2:DescribeRegions','shield:ListProtections','shield:GetSubscriptionState'}
    assert aws.FETCHERS['aws_region']is native.aws_region
    assert aws.FETCHERS['shield_protection_region']is native.shield_protection_region


def test_full_region_collector_to_logging_decision_reuses_region_discovery(sdk,monkeypatch):
    session,add=sdk;sts,ec2,trail=add('sts'),add('ec2'),add('cloudtrail')
    arn=f'arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/audit'
    sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/reviewer','UserId':'reviewer'}, {})
    ec2.add_response('describe_regions',{'Regions':[{'RegionName':REGION,'OptInStatus':'opt-in-not-required'}]}, {'AllRegions':True})
    trail.add_response('describe_trails',{'trailList':[{'TrailARN':arn,'Name':'audit','HomeRegion':REGION,'IsMultiRegionTrail':False}]}, {'includeShadowTrails':True})
    trail.add_response('get_trail_status',{'IsLogging':True},{'Name':arn})
    trail.add_response('get_event_selectors',{'TrailARN':arn,'EventSelectors':[]},{'TrailName':arn})
    trail.add_response('get_insight_selectors',{'TrailARN':arn,'InsightSelectors':[]},{'TrailName':arn})
    monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'test-pinned'))
    snapshot=collect(aws,{'provider':'aws','scopes':[ACCOUNT],'options':{'service_concurrency':1,'retry_attempts':1}},['aws_region','cloudtrail_account_inventory'])
    assert [f['status']for f in evaluate_snapshot(snapshot,checks=[REGION_CHECK])['findings']]==['PASS']
    assert snapshot['metadata']['calls']==6 and snapshot['metadata']['cache_hits']>=1
    for stub in (sts,ec2,trail):stub.assert_no_pending_responses()
