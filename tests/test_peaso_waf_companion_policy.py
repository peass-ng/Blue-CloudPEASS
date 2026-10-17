"""WAF companion reads preserve the existing customer's grants and trust."""
import copy
import json
from pathlib import Path
import pytest
from scripts import peaso_deploy_customer_policy as policy

EXPECTED={
 'appsync:GetWebACLForResource','appsync:ListResourcesForWebACL',
 'elasticloadbalancing:DescribeWebACLAssociation','cognito-idp:ListResourcesForWebACL',
 'apprunner:ListAssociatedServicesForWebAcl','ec2:DescribeVerifiedAccessInstanceWebAclAssociations',
}

def actions(document):
 return {a for s in document['Statement']for a in ([s['Action']]if isinstance(s['Action'],str)else s['Action'])}

def test_default_companion_policy_preserves_three_existing_documents_and_scopes():
 # This comparison predates the Budgets/tag/Resolver/SageMaker grants; the active template
 # is checked separately below against the complete current generator.
 from peaso.collectors.aws import READ_ACTIONS
 historical_actions=(READ_ACTIONS|policy.PRESERVED_TEMPLATE_READ_ACTIONS)-({
  ('budgets','describe_budget_actions_for_account'),('budgets','describe_budget_action'),
  ('ec2','describe_tags'),('lambda','list_tags'),
  ('route53resolver','list_firewall_domain_lists'),('sagemaker','list_endpoints'),
  ('sagemaker','describe_endpoint'),('sagemaker','list_monitoring_executions'),
    ('iam', 'get_role'),
    ('iam', 'get_context_keys_for_principal_policy'),
    ('iam', 'simulate_principal_policy'),
    ('codecommit', 'list_repositories'),
    ('codecommit', 'list_pull_requests'),
    ('codecommit', 'get_pull_request'),
    ('codecommit', 'describe_pull_request_events'),
    ('codecommit', 'get_pull_request_approval_states'),
 } | {('controltower', 'list_landing_zones'), ('controltower', 'get_landing_zone')})
 logical=policy.build_policy(historical_actions);documents=policy.split_policy(logical)
 baseline=json.loads((policy.REVIEWED_ROLE_PATH.parent/'customer-role-a57cdf166f64c9ad96a367a48fb62e54754a58a89ed767119f9dc46c05e46980.json').read_text())
 old=[baseline['Resources'][f'CspmConfigurationReadOnly{i}']['Properties']['PolicyDocument']for i in range(1,4)]
 assert documents[:3]==old and len(documents)==4
 assert actions(documents[3])==EXPECTED
 assert all(policy.policy_size(d)<=6144 for d in documents)
 wildcard={a for s in documents[3]['Statement']if s['Resource']=='*'for a in ([s['Action']]if isinstance(s['Action'],str)else s['Action'])}
 assert wildcard=={'appsync:ListResourcesForWebACL','elasticloadbalancing:DescribeWebACLAssociation','ec2:DescribeVerifiedAccessInstanceWebAclAssociations'}
 scoped={s['Action']:s['Resource']['Fn::Sub']for s in documents[3]['Statement']if s['Resource']!='*'}
 assert scoped=={'appsync:GetWebACLForResource':'arn:${AWS::Partition}:appsync:*:${AWS::AccountId}:apis/*','cognito-idp:ListResourcesForWebACL':'arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:regional/webacl/*/*','apprunner:ListAssociatedServicesForWebAcl':'arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:regional/webacl/*/*'}
 for s in documents[3]['Statement']:
  assert s['Effect']=='Allow'
  if s['Resource']!='*':
   arn=s['Resource']['Fn::Sub'];assert '${AWS::Partition}'in arn and '${AWS::AccountId}'in arn
 assert all(not any(c in a for c in '*?')and a.split(':')[1].startswith(('Get','List','Describe'))for a in EXPECTED)

@pytest.mark.parametrize('operation,expected',[
 (('wafv2','get_web_acl_for_resource'),{'appsync:GetWebACLForResource'}),
 (('wafv2','list_resources_for_web_acl'),EXPECTED-{'appsync:GetWebACLForResource'}),
 (('ec2','describe_instances'),set()),
])
def test_only_requested_waf_operations_add_companion_reads(operation,expected):
 logical=policy.build_policy({operation},include_credential_report_generation=False)
 assert actions(logical)&EXPECTED==expected
 assert all(policy.policy_size(d)<=6144 for d in policy.split_policy(logical))

def test_refresh_is_idempotent_and_preserves_role_and_every_existing_resource(tmp_path,monkeypatch):
 # Replay the accepted historical read universe; the current-role transition is tested separately.
 from peaso.collectors import aws
 monkeypatch.setattr(aws,'READ_ACTIONS',set(aws.READ_ACTIONS)-({('route53resolver','list_firewall_domain_lists'),('sagemaker','list_endpoints'),('sagemaker','describe_endpoint'),('sagemaker','list_monitoring_executions'),('iam', 'get_role'),('iam', 'get_context_keys_for_principal_policy'),('iam', 'simulate_principal_policy'),('codecommit', 'list_repositories'),('codecommit', 'list_pull_requests'),('codecommit', 'get_pull_request'),('codecommit', 'describe_pull_request_events'),('codecommit', 'get_pull_request_approval_states')} | {('controltower', 'list_landing_zones'), ('controltower', 'get_landing_zone')}))
 folder=tmp_path/'infra/aws';folder.mkdir(parents=True)
 original=json.loads((policy.REVIEWED_ROLE_PATH.parent/'customer-role-a57cdf166f64c9ad96a367a48fb62e54754a58a89ed767119f9dc46c05e46980.json').read_text())
 path=folder/'customer-role.json';path.write_text(json.dumps(original))
 policy.refresh(tmp_path);first=path.read_bytes();updated=json.loads(first)
 assert all(updated['Resources'][key]==value for key,value in original['Resources'].items())
 assert set(updated['Resources'])-set(original['Resources'])=={'CspmConfigurationReadOnly4'}
 assert updated['Parameters']==original['Parameters']and updated['Outputs']==original['Outputs']
 assert len(first)<26000
 policy.refresh(tmp_path);assert path.read_bytes()==first


def test_unknown_companion_mapping_fails_closed(monkeypatch):
 rows=copy.deepcopy(policy.WAF_ASSOCIATION_STATEMENTS)
 rows[('wafv2','get_web_acl_for_resource')][0]['Action']='iam:CreateRole'
 monkeypatch.setattr(policy,'WAF_ASSOCIATION_STATEMENTS',rows)
 with pytest.raises(ValueError,match='reference review'):
  policy.build_policy({('wafv2','get_web_acl_for_resource')})


def test_companions_still_obey_the_existing_policy_count_budget(monkeypatch):
 monkeypatch.setattr(policy,'IAM_MANAGED_POLICIES_PER_ROLE',3)
 with pytest.raises(ValueError,match='existing IAM policy budgets'):
  policy.build_policy()


def test_active_template_matches_generator_and_immutable_archive():
 import hashlib
 folder=Path(policy.__file__).resolve().parents[1]/'infra/aws';raw=(folder/'customer-role.json').read_bytes()
 assert raw==(folder/('customer-role-'+hashlib.sha256(raw).hexdigest()+'.json')).read_bytes()
 template=json.loads(raw)
 documents=[r['Properties']['PolicyDocument']for name,r in sorted(template['Resources'].items())if r['Type']=='AWS::IAM::ManagedPolicy']
 assert documents==policy.split_policy(policy.build_policy())
