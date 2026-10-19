"""Only selected IAM metadata checks may invoke two AWS-classified Read report APIs."""
from copy import deepcopy
from unittest.mock import Mock
import boto3
from botocore.stub import Stubber
import pytest
from peaso.collectors import aws
from peaso.engine import collect_snapshot
from peaso.snapshot import make_snapshot


@pytest.mark.parametrize('operation', ['generate_credential_report','generate_service_last_accessed_details','create_role','create_access_key','update_login_profile'])
def test_default_requests_still_refuses_report_jobs_and_all_mutations(operation):
    requests=aws.Requests({});session=Mock()
    with pytest.raises(aws.ReadFailure):requests.call(session,'iam','us-east-1',operation)
    session.client.assert_not_called()


@pytest.mark.parametrize('selection,credential,usage', [
    (['aws.iam.console_mfa'],False,False),
    (['aws.claude_a.iam.user_bedrock_access_not_stale'],False,True),
    (['aws.claude_a.iam.role_bedrock_access_not_stale'],False,True),
    (['aws.claude_a.iam.user_long_lived_keys_only_iam_sts'],False,True),
    (['aws.claude_a.iam.user_sagemaker_access_not_stale'],False,True),
    (['aws.iam.root_mfa'],True,False),
])
def test_selected_checks_overwrite_user_supplied_internal_report_flags(monkeypatch,selection,credential,usage):
    seen={}
    def collect(connector,requirements):
        seen.update(connector['options']);return make_snapshot('aws',['123456789012/us-east-1'],[])
    monkeypatch.setattr('peaso.collectors.collect_live',collect)
    collect_snapshot({'connector':{'provider':'aws','options':{'_iam_report_generation_requested':True,
        '_iam_credential_report_generation_requested':True,'_iam_service_access_reports_requested':True}},'checks':selection})
    assert seen['_iam_credential_report_generation_requested'] is credential
    assert seen['_iam_service_access_reports_requested'] is usage
    assert seen['_iam_report_generation_requested'] is (credential or usage)


@pytest.mark.parametrize('field',['_iam_report_generation_requested','_iam_credential_report_generation_requested','_iam_service_access_reports_requested'])
def test_internal_report_flags_are_strict_boolean(field):
    with pytest.raises(ValueError):aws.Requests({field:'true'})


def test_two_report_reads_are_sdk_allowed_and_resource_mutations_remain_refused():
    session=boto3.Session(aws_access_key_id='fixture',aws_secret_access_key='fixture',region_name='us-east-1');client=session.client('iam')
    requests=aws.Requests({'_iam_report_generation_requested':True});requests._clients[(id(session),'iam','us-east-1')]=client
    with Stubber(client) as stub:
        stub.add_response('generate_credential_report',{'State':'COMPLETE'},{})
        stub.add_response('generate_service_last_accessed_details',{'JobId':'12345678-1234-1234-1234-123456789012'},
                          {'Arn':'arn:aws:iam::123456789012:user/reviewer','Granularity':'SERVICE_LEVEL'})
        assert requests.call(session,'iam','us-east-1','generate_credential_report')['State']=='COMPLETE'
        assert requests.call(session,'iam','us-east-1','generate_service_last_accessed_details',
            Arn='arn:aws:iam::123456789012:user/reviewer',Granularity='SERVICE_LEVEL')['JobId']
        for operation in ['create_role','create_access_key','delete_role','update_assume_role_policy','generate_organizations_access_report']:
            with pytest.raises(aws.ReadFailure):requests.call(session,'iam','us-east-1',operation)
        stub.assert_no_pending_responses()
    assert requests.calls==2 and requests.evidence_generations==requests.service_last_accessed_generations==1


def test_report_role_permission_scope_is_exact_and_documented():
    from scripts.peaso_deploy_customer_policy import build_policy, IAM_REPORT_READ_REFERENCES
    policy = build_policy({('iam', 'generate_credential_report'), ('iam', 'generate_service_last_accessed_details')})
    actions = {action for statement in policy['Statement']
               for action in ([statement['Action']] if isinstance(statement['Action'], str) else statement['Action'])}
    assert actions == set(IAM_REPORT_READ_REFERENCES) == {'iam:GenerateCredentialReport', 'iam:GenerateServiceLastAccessedDetails'}
    assert all(statement['Effect'] == 'Allow' and statement['Resource'] == '*' for statement in policy['Statement'])
    assert set(IAM_REPORT_READ_REFERENCES.values()) == {'https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html'}
