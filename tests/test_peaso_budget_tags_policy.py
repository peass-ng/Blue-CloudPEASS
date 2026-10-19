"""Native Budgets/tag metadata grants preserve the existing role boundary."""
import copy,itertools,json,hashlib
import pytest
from scripts import peaso_deploy_customer_policy as policy
from tests.customer_policy_history import historical_role_bytes, historical_derivative_sha256

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


def test_four_metadata_reads_preserve_previous_policy_partitions_and_trust():
 before_hash='0eeba5694a23a8fd93013b1c15dd2bfbc3f0ec4de7554a9a9405b0306b611e6d'
 after_hash='2b6825b57ea8d5a443b35e5fda86bc97eda6324721dcfd002b52a8cf356cd92f'
 before_raw=historical_role_bytes(before_hash)
 after_raw=historical_role_bytes(after_hash)
 assert hashlib.sha256(before_raw).hexdigest()==historical_derivative_sha256(before_hash)
 assert hashlib.sha256(after_raw).hexdigest()==historical_derivative_sha256(after_hash)
 before=json.loads(before_raw);after=json.loads(after_raw)
 assert set(after['Resources'])==set(before['Resources'])
 for name,value in before['Resources'].items():
  if name!='CspmConfigurationReadOnly4':assert after['Resources'][name]==value
 assert after['Parameters']==before['Parameters'] and after['Outputs']==before['Outputs']
 old=before['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement']
 new=after['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement']
 assert new[:len(old)]==old
 extra=new[len(old):]
 assert extra==policy.build_policy(set(OPS),include_credential_report_generation=False)['Statement']
 assert {a for row in extra for a in ([row['Action']]if isinstance(row['Action'],str)else row['Action'])}==set(ACTIONS)
 assert [policy.policy_size(after['Resources'][f'CspmConfigurationReadOnly{i}']['Properties']['PolicyDocument']) for i in range(1,5)]==[6136,6129,5819,1422]

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


def test_next_four_reads_preserve_current_published_role_and_add_only_four_grants():
 from peaso.collectors import aws
 before_hash='2b6825b57ea8d5a443b35e5fda86bc97eda6324721dcfd002b52a8cf356cd92f'
 after_hash='7da8ecb219db8799e87cab5b4a632f6d40c7e4d6f5cb5c4cd1eea1a6fbdd2fe6'
 before_raw=historical_role_bytes(before_hash)
 after_raw=historical_role_bytes(after_hash)
 assert hashlib.sha256(before_raw).hexdigest()==historical_derivative_sha256(before_hash)
 assert hashlib.sha256(after_raw).hexdigest()==historical_derivative_sha256(after_hash)
 before=json.loads(before_raw);after=json.loads(after_raw)
 assert set(NEXT_OPS)<=set(aws.READ_ACTIONS)
 assert set(after['Resources'])==set(before['Resources'])
 for name,value in before['Resources'].items():
  if name!='CspmConfigurationReadOnly4':assert after['Resources'][name]==value
 assert after['Parameters']==before['Parameters'] and after['Outputs']==before['Outputs']
 old=before['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement']
 new=after['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement']
 assert new[:len(old)]==old
 extra=new[len(old):]
 assert extra==policy.build_policy(set(NEXT_OPS),include_credential_report_generation=False)['Statement']
 assert {a for row in extra for a in ([row['Action']]if isinstance(row['Action'],str)else row['Action'])}==set(NEXT_ACTIONS)
 assert [policy.policy_size(after['Resources'][f'CspmConfigurationReadOnly{i}']['Properties']['PolicyDocument']) for i in range(1,5)]==[6136,6129,5819,1976]
