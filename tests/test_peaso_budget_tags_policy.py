"""Native Budgets/tag metadata grants preserve the existing role boundary."""
import copy,itertools,json
from pathlib import Path
import pytest
from scripts import peaso_deploy_customer_policy as policy

OPS=[('budgets','describe_budget_actions_for_account'),('budgets','describe_budget_action'),('ec2','describe_tags'),('lambda','list_tags')]
ACTIONS=['budgets:DescribeBudgetActionsForAccount','budgets:DescribeBudgetAction','ec2:DescribeTags','lambda:ListTags']
SUBSETS=[tuple(i for i in range(4)if bits&(1<<i))for bits in range(1,16)]

@pytest.mark.parametrize('indices',SUBSETS)
def test_selected_metadata_grants_have_no_unrequested_actions_or_scoped_wildcards(indices):
 logical=policy.build_policy({OPS[i]for i in indices},include_credential_report_generation=False)
 documents=policy.split_policy(logical)
 statements=[s for d in documents for s in d['Statement']]
 granted={a for s in statements for a in([s['Action']]if isinstance(s['Action'],str)else s['Action'])}
 assert granted=={ACTIONS[i]for i in indices}
 for s in statements:
  actions=[s['Action']]if isinstance(s['Action'],str)else s['Action']
  if 'lambda:ListTags'in actions:assert s['Resource']=={'Fn::Sub':'arn:${AWS::Partition}:lambda:*:${AWS::AccountId}:function:*'}
  elif 'budgets:DescribeBudgetAction'in actions:assert s['Resource']=={'Fn::Sub':'arn:${AWS::Partition}:budgets::${AWS::AccountId}:budget/*/action/*'}
  else:assert s['Resource']=='*'
 assert all(policy.policy_size(d)<=6144 for d in documents)

@pytest.mark.parametrize('service,operation',[('budgets','execute_budget_action'),('budgets','create_budget_action'),('ec2','create_tags'),('lambda','tag_resource'),('lambda','get_function'),('secretsmanager','get_secret_value'),('ssm','get_parameter')])
def test_mutation_or_secret_operations_cannot_enter_metadata_grant(service,operation):
 with pytest.raises(ValueError):policy.build_policy({(service,operation)},include_credential_report_generation=False)


def test_metadata_mapping_rejects_a_verified_but_wrong_alias(monkeypatch):
 monkeypatch.setattr(policy,'iam_action',lambda *args:'lambda:ListTags')
 with pytest.raises(ValueError,match='mapping differs'):policy.build_policy({OPS[1]},include_credential_report_generation=False)


def test_four_metadata_reads_preserve_previous_policy_partitions_and_trust(monkeypatch,tmp_path):
 from peaso.collectors import aws
 root=Path(__file__).resolve().parents[1];old=(root/'infra/aws/customer-role-0eeba5694a23a8fd93013b1c15dd2bfbc3f0ec4de7554a9a9405b0306b611e6d.json').read_bytes();d=json.loads(old)
 (tmp_path/'infra/aws').mkdir(parents=True);(tmp_path/'infra/aws/customer-role.json').write_bytes(old)
 monkeypatch.setattr(aws,'READ_ACTIONS',(set(aws.READ_ACTIONS)-({('route53resolver','list_firewall_domain_lists'),('sagemaker','list_endpoints'),('sagemaker','describe_endpoint'),('sagemaker','list_monitoring_executions'),('iam', 'get_role'),('iam', 'get_context_keys_for_principal_policy'),('iam', 'simulate_principal_policy'),('codecommit', 'list_repositories'),('codecommit', 'list_pull_requests'),('codecommit', 'get_pull_request'),('codecommit', 'describe_pull_request_events'),('codecommit', 'get_pull_request_approval_states')} | {('controltower', 'list_landing_zones'), ('controltower', 'get_landing_zone')}))|set(OPS));policy.refresh(tmp_path);new=json.loads((tmp_path/'infra/aws/customer-role.json').read_bytes())
 assert set(new['Resources'])==set(d['Resources'])
 for name,value in d['Resources'].items():
  if name!='CspmConfigurationReadOnly4':assert new['Resources'][name]==value
 assert new['Parameters']==d['Parameters'] and new['Outputs']==d['Outputs']
 old_statements=d['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement'];new_statements=new['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement']
 assert new_statements[:len(old_statements)]==old_statements
 extra=new_statements[len(old_statements):];assert {a for s in extra for a in([s['Action']]if isinstance(s['Action'],str)else s['Action'])}==set(ACTIONS)
 before=(tmp_path/'infra/aws/customer-role.json').read_bytes();policy.refresh(tmp_path);assert(tmp_path/'infra/aws/customer-role.json').read_bytes()==before


NEXT_OPS=[('route53resolver','list_firewall_domain_lists'),('sagemaker','list_endpoints'),('sagemaker','describe_endpoint'),('sagemaker','list_monitoring_executions')]
NEXT_ACTIONS=['route53resolver:ListFirewallDomainLists','sagemaker:ListEndpoints','sagemaker:DescribeEndpoint','sagemaker:ListMonitoringExecutions']

@pytest.mark.parametrize('indices',SUBSETS)
def test_next_native_reads_are_exact_and_endpoint_metadata_is_account_scoped(indices):
 logical=policy.build_policy({NEXT_OPS[i]for i in indices},include_credential_report_generation=False)
 docs=policy.split_policy(logical);statements=[s for d in docs for s in d['Statement']]
 granted={a for s in statements for a in([s['Action']]if isinstance(s['Action'],str)else s['Action'])}
 assert granted=={NEXT_ACTIONS[i]for i in indices}
 for s in statements:
  if s['Action']=='sagemaker:DescribeEndpoint':assert s['Resource']=={'Fn::Sub':'arn:${AWS::Partition}:sagemaker:*:${AWS::AccountId}:endpoint/*'}
  else:assert s['Resource']=='*'
 assert all(policy.policy_size(d)<=6144 for d in docs)


def test_next_four_reads_preserve_current_published_role_and_add_only_four_grants(monkeypatch,tmp_path):
 from peaso.collectors import aws
 root=Path(__file__).resolve().parents[1];old=(root/'infra/aws/customer-role-2b6825b57ea8d5a443b35e5fda86bc97eda6324721dcfd002b52a8cf356cd92f.json').read_bytes();d=json.loads(old)
 (tmp_path/'infra/aws').mkdir(parents=True);(tmp_path/'infra/aws/customer-role.json').write_bytes(old)
 assert set(NEXT_OPS)<=set(aws.READ_ACTIONS)
 monkeypatch.setattr(aws,'READ_ACTIONS',set(aws.READ_ACTIONS)-({('codecommit', 'get_pull_request'), ('iam', 'simulate_principal_policy'), ('codecommit', 'list_pull_requests'), ('codecommit', 'describe_pull_request_events'), ('codecommit', 'get_pull_request_approval_states'), ('codecommit', 'list_repositories'), ('iam', 'get_role'), ('iam', 'get_context_keys_for_principal_policy')} | {('controltower', 'list_landing_zones'), ('controltower', 'get_landing_zone')}))
 policy.refresh(tmp_path);new=json.loads((tmp_path/'infra/aws/customer-role.json').read_bytes())
 assert set(new['Resources'])==set(d['Resources'])
 for n,value in d['Resources'].items():
  if n!='CspmConfigurationReadOnly4':assert new['Resources'][n]==value
 assert new['Parameters']==d['Parameters']and new['Outputs']==d['Outputs']
 before=d['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement'];after=new['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement'];assert after[:len(before)]==before
 extra=after[len(before):];assert len(extra)==4
 assert {a for s in extra for a in([s['Action']]if isinstance(s['Action'],str)else s['Action'])}==set(NEXT_ACTIONS)
 content=(tmp_path/'infra/aws/customer-role.json').read_bytes();policy.refresh(tmp_path);assert(tmp_path/'infra/aws/customer-role.json').read_bytes()==content
