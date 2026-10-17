"""Approved intent plus real botocore API responses, through collect_live→engine."""
import copy,json
from datetime import datetime,timezone
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.collectors import aws_operational_groups_native as native
from peaso.engine import evaluate_snapshot
SCOPE=ACCOUNT+'/'+REGION
RECOVERY='aws.nist.sc_36_coverage'
CAPACITY='aws.nist.sc_5_2_coverage'
INSTANCE='i-11111111111111111'
ASG=f'arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:11111111-1111-1111-1111-111111111111:autoScalingGroupName/workers'

def policy():
 return {'recovery_groups':[{'scope':SCOPE,'id':'critical','members':[{'kind':'instance','id':INSTANCE},{'kind':'rds_instance','id':'database'}]}],
         'capacity_groups':[{'scope':SCOPE,'id':'workers','autoscaling_group_arn':ASG,'minimum_capacity':2,'capacity_unit':'units'}]}

def capture(sdk,monkeypatch,mode='ok',selected=None):
 session,add=sdk;sts=add('sts');ec2=add('ec2');rds=add('rds');asg=add('autoscaling')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/reviewer','UserId':'reviewer'}, {})
 instance={'InstanceId':INSTANCE,'Placement':{'AvailabilityZone':REGION+'a'},'State':{'Name':'stopped'if mode=='stopped_instance'else'running'}}
 db={'DBInstanceIdentifier':'database','DBInstanceArn':f'arn:aws:rds:{REGION}:{ACCOUNT}:db:database','DBInstanceStatus':'available','AvailabilityZone':REGION+('a'if mode=='same_zone'else'b')}
 if mode=='foreign_zone':db['AvailabilityZone']='eu-west-1a'
 if mode=='bad_state':db['DBInstanceStatus']='invented'
 if mode=='stopped_database':db['DBInstanceStatus']='stopped'
 if mode=='missing_placement':instance.pop('Placement')
 group={'AutoScalingGroupName':'workers','AutoScalingGroupARN':ASG,'MinSize':0,'MaxSize':10,'DesiredCapacity':1 if mode=='low_capacity'else 3,
        'AvailabilityZones':[REGION+'a']if mode=='one_capacity_zone'else[REGION+'a',REGION+'b'],'CreatedTime':datetime.now(timezone.utc),'DefaultCooldown':300,'HealthCheckType':'EC2'}
 if mode=='capacity_unit_mismatch':group['DesiredCapacityType']='vcpu'
 if mode=='capacity_deleting':group['Status']='Delete in progress'
 if mode=='foreign_asg':group['AutoScalingGroupARN']=ASG.replace(ACCOUNT,'999999999999')
 if mode=='capacity_foreign_zone':group['AvailabilityZones']=['eu-west-1a','eu-west-1b']
 if mode=='duplicate_zone':group['AvailabilityZones']=[REGION+'a',REGION+'a']
 if mode=='wrong_asg_name':group['AutoScalingGroupName']='other'
 if mode=='explicit_units':group['DesiredCapacityType']='units'
 if mode in('vcpu_units','memory_units'):group['DesiredCapacityType']='vcpu'if mode=='vcpu_units'else'memory-mib'
 approval=policy()
 if mode in('vcpu_units','memory_units'):approval['capacity_groups'][0]['capacity_unit']=group['DesiredCapacityType']
 if mode=='missing_policy':approval=None
 if mode=='foreign_policy':
  for rows in approval.values():rows[0]['scope']='999999999999/'+REGION
  approval['capacity_groups'][0]['autoscaling_group_arn']=ASG.replace(ACCOUNT,'999999999999')
 if mode=='unresolved_member':approval['recovery_groups'][0]['members'][0]['id']='i-22222222222222222'
 wants_recovery=selected in(None,RECOVERY);wants_capacity=selected in(None,CAPACITY)
 if wants_recovery:
  if mode=='ec2_denied':ec2.add_client_error('describe_instances','UnauthorizedOperation',http_status_code=403,expected_params={})
  else:
   ec2.add_response('describe_instances',{'Reservations':[{'Instances':[instance]}]}, {})
   # Existing EC2 inventory enrichments remain real SDK reads, with no guest execution.
   ec2.add_response('describe_instance_attribute',{'InstanceId':INSTANCE,'UserData':{}},{'InstanceId':INSTANCE,'Attribute':'userData'})
   ec2.add_response('describe_instance_attribute',{'InstanceId':INSTANCE,'DisableApiTermination':{'Value':False}},{'InstanceId':INSTANCE,'Attribute':'disableApiTermination'})
  if mode=='rds_denied':rds.add_client_error('describe_db_instances','AccessDenied',http_status_code=403,expected_params={})
  else:rds.add_response('describe_db_instances',{'DBInstances':[db]}, {})
 if wants_capacity and mode not in('missing_policy','foreign_policy'):
  if mode=='asg_denied':asg.add_client_error('describe_auto_scaling_groups','AccessDenied',http_status_code=403,expected_params={})
  else:asg.add_response('describe_auto_scaling_groups',{'AutoScalingGroups':[]if mode=='missing_asg'else[group],**({'NextToken':'more'}if mode=='partial_asg'else{})}, {})
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture-pinned'))
 options={'service_concurrency':1,'retry_attempts':1,**({'max_pages':1}if mode=='partial_asg'else{}),'compliance_parameters':{}if approval is None else{'operational_groups':approval}}
 connector={'provider':'aws','scopes':[SCOPE],'options':options}
 if selected:
  from peaso.engine import collect_snapshot
  snapshot=collect_snapshot({'connector':connector,'checks':[selected]})
 else:snapshot=collect_live(connector,['recovery_group','instance','rds_instance','capacity_group'])
 result=evaluate_snapshot(snapshot,checks=[selected]if selected else[RECOVERY,CAPACITY])
 for stub in (sts,ec2,rds,asg):stub.assert_no_pending_responses()
 return {cid:[f for f in result['findings']if f['check_id']==cid][-1]for cid in([selected]if selected else[RECOVERY,CAPACITY])},snapshot

@pytest.mark.parametrize('mode,recovery,capacity',[
 ('ok','PASS','PASS'),('explicit_units','PASS','PASS'),('vcpu_units','PASS','PASS'),('memory_units','PASS','PASS'),('same_zone','FAIL','PASS'),('stopped_instance','FAIL','PASS'),('stopped_database','FAIL','PASS'),('missing_placement','UNKNOWN','PASS'),
 ('foreign_zone','UNKNOWN','PASS'),('bad_state','UNKNOWN','PASS'),('unresolved_member','UNKNOWN','PASS'),
 ('low_capacity','PASS','FAIL'),('one_capacity_zone','PASS','FAIL'),('capacity_unit_mismatch','PASS','UNKNOWN'),
 ('capacity_deleting','PASS','UNKNOWN'),('foreign_asg','PASS','UNKNOWN'),('capacity_foreign_zone','PASS','UNKNOWN'),('duplicate_zone','PASS','UNKNOWN'),
 ('wrong_asg_name','PASS','UNKNOWN'),('missing_asg','PASS','UNKNOWN'),('partial_asg','PASS','UNKNOWN'),('asg_denied','PASS','DENIED'),
 ('ec2_denied','DENIED','PASS'),('rds_denied','DENIED','PASS'),('missing_policy','UNKNOWN','UNKNOWN'),('foreign_policy','UNKNOWN','UNKNOWN')])
def test_actual_native_collection_and_frozen_predicates(sdk,monkeypatch,mode,recovery,capacity):
 findings,snapshot=capture(sdk,monkeypatch,mode)
 assert {k:v['status']for k,v in findings.items()}=={RECOVERY:recovery,CAPACITY:capacity},findings
 if mode=='ok':
  assert snapshot['metadata']['cache_hits']>=2  # EC2 and RDS inventory reads are shared.
  row=next(c for c in snapshot['collections']if c['type']=='capacity_group')['items'][0]
  assert row['ConfiguredCapacity']==3 and row['DocumentedMinimum']==2
  assert row['_provenance']['capacity_semantics']=='configured_desired_capacity'

@pytest.mark.parametrize('cid',[RECOVERY,CAPACITY])
def test_selected_runtime_plan_native_producer(sdk,monkeypatch,cid):
 findings,_=capture(sdk,monkeypatch,selected=cid)
 assert findings[cid]['status']=='PASS',findings

def test_no_new_read_actions_required():
 assert native.READ_ACTIONS=={(aws.SPECS[k][0],aws.SPECS[k][1])for k in ('instance','rds_instance','autoscaling_group')}
 assert native.READ_ACTIONS<=aws.READ_ACTIONS
 assert native.FETCHERS['capacity_group']is aws.FETCHERS['capacity_group']

@pytest.mark.parametrize('change',[
 lambda p:p['capacity_groups'][0].update(minimum_capacity=0),
 lambda p:p['capacity_groups'][0].update(minimum_capacity=True),
 lambda p:p['capacity_groups'][0].update(ConfiguredCapacity=10),
 lambda p:p['capacity_groups'][0].update(capacity_unit='invented'),
 lambda p:p['recovery_groups'][0].update(members=[]),
 lambda p:p['recovery_groups'][0]['members'].append(copy.deepcopy(p['recovery_groups'][0]['members'][0])),
 lambda p:p['recovery_groups'][0]['members'][0].update(availability_zone='us-east-1b'),
 lambda p:p['recovery_groups'][0].update(state='running')])
def test_normative_policy_rejects_fabricated_observations(change):
 approval=policy();change(approval)
 with pytest.raises(ValueError):native.normalize({'compliance_parameters':{'operational_groups':approval}})

def test_actual_aws_service_authorization_arn_grammar_not_colon_name_separator():
 approval=policy()
 assert native.normalize({'compliance_parameters':{'operational_groups':approval}})==approval
 approval['capacity_groups'][0]['autoscaling_group_arn']=ASG.replace(':autoScalingGroupName/',':autoScalingGroupName:')
 with pytest.raises(ValueError):native.normalize({'compliance_parameters':{'operational_groups':approval}})
