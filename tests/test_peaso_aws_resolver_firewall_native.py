"""SDK-shaped Resolver inventory through collect_live and unchanged signed SW44."""
import copy,json
import pytest
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.collectors.aws_resolver_firewall_native import normalize
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
VPC='vpc-12345678';GROUP='rslvr-frg-example';LID='rslvr-fdl-example';AID='rslvr-frgassoc-example'
CHECK='aws_resolver_managed_domain_lists_block'
def capture(sdk,monkeypatch,mode,planned=False,hosted=False):
 session,add=sdk;sts=add('sts');ec2=add('ec2');dns=add('route53resolver')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/fixture','UserId':'fixture'},{})
 options={'regions':[REGION],'retry_attempts':1,'compliance_parameters':{'aws_resolver_firewall':[{'scope':ACCOUNT+'/'+REGION,'vpc_id':VPC,'approved_managed_domain_list_ids':[LID]}]}}
 if hosted:
  options.pop('retry_attempts')
  from types import SimpleNamespace
  from peaso.server.validation import validate_connector
  validate_connector('aws',{'method':'assume_role','role_arn':f'arn:aws:iam::{ACCOUNT}:role/ReadOnly','external_id':'peaso-fixture'},options,SimpleNamespace(auth_mode='cognito'),server_external_id=True)
 if mode=='missing_policy':options.pop('compliance_parameters')
 if mode=='no_selected':options['compliance_parameters']['aws_resolver_firewall']=[]
 vpcs=[{'VpcId':VPC,'OwnerId':ACCOUNT,'State':'available'}]
 if mode=='foreign_vpc':vpcs[0]['OwnerId']='999999999999'
 if mode=='duplicate_vpc':vpcs*=2
 if mode=='empty_vpcs':vpcs=[]
 ec2.add_response('describe_vpcs',{'Vpcs':vpcs},{})
 listing={'Id':LID,'Arn':f'arn:aws:route53resolver:{REGION}:{ACCOUNT}:firewall-domain-list/{LID}','ManagedOwnerName':'Route 53 Resolver DNS Firewall'}
 if mode=='not_managed':listing.pop('ManagedOwnerName')
 if mode=='foreign_list':listing['Arn']=listing['Arn'].replace(REGION,'us-west-2')
 if mode=='domain_denied':dns.add_client_error('list_firewall_domain_lists','AccessDeniedException',expected_params={})
 else:dns.add_response('list_firewall_domain_lists',{'FirewallDomainLists':[listing],**({'NextToken':'next'}if mode in('domain_paged','domain_partial')else{})},{})
 if mode=='domain_paged':dns.add_response('list_firewall_domain_lists',{'FirewallDomainLists':[]},{'NextToken':'next'})
 assoc={'Id':AID,'Arn':f'arn:aws:route53resolver:{REGION}:{ACCOUNT}:firewall-rule-group-association/{AID}','FirewallRuleGroupId':GROUP,'VpcId':VPC,'Priority':101,'Status':'COMPLETE'}
 if mode=='foreign_association':assoc['Arn']=assoc['Arn'].replace(ACCOUNT,'999999999999')
 if mode=='foreign_assoc_vpc':assoc['VpcId']='vpc-99999999'
 if mode=='transition':assoc['Status']='UPDATING'
 associations=[]if mode=='no_association'else[assoc]
 if mode=='duplicate_association':associations*=2
 if mode=='association_denied':dns.add_client_error('list_firewall_rule_group_associations','AccessDeniedException',expected_params={})
 else:dns.add_response('list_firewall_rule_group_associations',{'FirewallRuleGroupAssociations':associations,**({'NextToken':'next'}if mode in('association_paged','association_partial')else{})},{})
 if mode=='association_paged':dns.add_response('list_firewall_rule_group_associations',{'FirewallRuleGroupAssociations':[]},{'NextToken':'next'})
 rule={'FirewallRuleGroupId':GROUP,'FirewallDomainListId':LID,'Priority':101,'Action':'BLOCK','BlockResponse':'NXDOMAIN','Status':'COMPLETE'}
 if mode=='allow':rule['Action']='ALLOW';rule.pop('BlockResponse')
 if mode=='mixed':extra={**rule,'FirewallDomainListId':'rslvr-fdl-other','Priority':102,'Action':'ALLOW'};extra.pop('BlockResponse')
 if mode=='foreign_group':rule['FirewallRuleGroupId']='rslvr-frg-other'
 if mode=='missing_list_id':rule.pop('FirewallDomainListId')
 if mode=='qtype':rule['Qtype']='A'
 if mode=='redirect':rule['FirewallDomainRedirectionAction']='TRUST_REDIRECTION_DOMAIN'
 if mode=='override':rule['BlockResponse']='OVERRIDE'
 if mode=='rule_transition':rule['Status']='UPDATING'
 if mode=='unknown_rule_status':rule['Status']='UNRECOGNIZED'
 if mode=='missing_rule_status':rule.pop('Status')
 rules=[]if mode=='no_rules'else[rule]
 if mode=='mixed':rules.append(extra)
 if mode=='duplicate_rule':rules*=2
 if mode=='rules_denied':dns.add_client_error('list_firewall_rules','AccessDeniedException',expected_params={'FirewallRuleGroupId':GROUP})
 else:dns.add_response('list_firewall_rules',{'FirewallRules':rules,**({'NextToken':'next'}if mode in('rules_paged','rules_partial')else{})},{'FirewallRuleGroupId':GROUP})
 if mode=='rules_paged':dns.add_response('list_firewall_rules',{'FirewallRules':[]},{'FirewallRuleGroupId':GROUP,'NextToken':'next'})
 if mode.endswith('_partial'):options['max_pages']=1
 monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture'))
 connector={'provider':'aws','scopes':[ACCOUNT],'options':options}
 snap=collect_snapshot({'connector':connector,'checks':[CHECK]})if planned else collect_live(connector,['resolver_firewall'])
 f=evaluate_snapshot(snap,checks=[CHECK],include_not_applicable=True)['findings']
 assert f
 if mode in('good','domain_paged','association_paged','rules_paged'):
  sts.assert_no_pending_responses();ec2.assert_no_pending_responses();dns.assert_no_pending_responses()
 return f[0],snap

@pytest.mark.parametrize('mode,status',[
 ('good','PASS'),('domain_paged','PASS'),('association_paged','PASS'),('rules_paged','PASS'),
 ('no_rules','FAIL'),('no_association','FAIL'),('allow','FAIL'),('mixed','UNKNOWN'),('qtype','UNKNOWN'),('redirect','UNKNOWN'),('override','UNKNOWN'),('rule_transition','UNKNOWN'),('unknown_rule_status','UNKNOWN'),('missing_rule_status','PASS'),
 ('missing_policy','UNKNOWN'),('no_selected','EMPTY'),('empty_vpcs','UNKNOWN'),('foreign_vpc','UNKNOWN'),('duplicate_vpc','UNKNOWN'),
 ('not_managed','UNKNOWN'),('foreign_list','UNKNOWN'),('domain_denied','DENIED'),('domain_partial','UNKNOWN'),
 ('foreign_association','UNKNOWN'),('foreign_assoc_vpc','UNKNOWN'),('transition','UNKNOWN'),('duplicate_association','UNKNOWN'),('association_denied','DENIED'),('association_partial','UNKNOWN'),
 ('foreign_group','UNKNOWN'),('missing_list_id','UNKNOWN'),('duplicate_rule','UNKNOWN'),('rules_denied','DENIED'),('rules_partial','UNKNOWN')])
def test_native_pipeline(sdk,monkeypatch,mode,status):
 finding,snap=capture(sdk,monkeypatch,mode)
 assert finding['status']==status,(finding,snap)

def test_actual_planner_activates_native_producer(sdk,monkeypatch):
 f,s=capture(sdk,monkeypatch,'good',True)
 assert f['status']=='PASS'
 assert any(x['type']=='resolver_firewall'and x['status']=='collected'for x in s['collections'])

@pytest.mark.parametrize('change',[{'scope':'999/global'},{'vpc_id':'vpc-evil'},{'approved_managed_domain_list_ids':[]},{'approved_managed_domain_list_ids':[LID,LID]},{'extra':True}])
def test_policy_rejects_malformed_normative_input(change):
 row={'scope':ACCOUNT+'/'+REGION,'vpc_id':VPC,'approved_managed_domain_list_ids':[LID]};row.update(change)
 with pytest.raises(ValueError):normalize({'compliance_parameters':{'aws_resolver_firewall':[row]}})

def test_no_implicit_approval_or_policy_mutation():
 assert normalize({})is None
 row={'scope':ACCOUNT+'/'+REGION,'vpc_id':VPC,'approved_managed_domain_list_ids':[LID]};options={'compliance_parameters':{'aws_resolver_firewall':[row]}}
 before=copy.deepcopy(options);normalized=normalize(options);normalized[ACCOUNT+'/'+REGION,VPC].append('rslvr-fdl-other');assert options==before


def test_hosted_validated_policy_reaches_real_native_engine(sdk,monkeypatch):
 finding,snapshot=capture(sdk,monkeypatch,'good',planned=True,hosted=True)
 assert finding['status']=='PASS'
 row=next(c['items'][0]for c in snapshot['collections']if c['type']=='resolver_firewall')
 assert row['ApprovedManagedDomainListIds']==[LID]
 assert row['_provenance']['configuration_only'] is True

@pytest.mark.parametrize('provider',['azure','gcp','k8s'])
def test_hosted_rejects_foreign_normative_namespace(provider):
 from fastapi import HTTPException
 from types import SimpleNamespace
 from peaso.server.validation import validate_connector
 options={'compliance_parameters':{'aws_resolver_firewall':[{'scope':ACCOUNT+'/'+REGION,'vpc_id':VPC,'approved_managed_domain_list_ids':[LID]}]}}
 with pytest.raises(HTTPException):validate_connector(provider,{},options,SimpleNamespace(auth_mode='cognito'))

def test_native_new_read_has_exact_iam_mapping():
 from scripts.peaso_deploy_customer_policy import build_policy
 doc=build_policy(read_actions={('route53resolver','list_firewall_domain_lists')},include_credential_report_generation=False,include_waf_association_companions=False)
 text=json.dumps(doc)
 assert 'route53resolver:ListFirewallDomainLists' in text
 assert 'route53resolver:*'not in text
