"""Provider-side report generation is forbidden even when a caller asks directly."""
from datetime import datetime, timezone
from unittest.mock import Mock
import pytest
from peaso.collectors import aws

@pytest.mark.parametrize('operation', ['generate_credential_report','generate_service_last_accessed_details'])
def test_generation_refused_before_client_or_budget(operation):
    session=Mock()
    requests=aws.Requests({})
    with pytest.raises(aws.ReadFailure) as error:
        requests.call(session,'iam','us-east-1',operation)
    assert error.value.code == 'non_read_operation'
    session.client.assert_not_called()
    assert requests.calls == requests.evidence_generations == requests.service_last_accessed_generations == 0

def test_existing_credential_report_remains_readable():
    client=Mock()
    client.get_credential_report.return_value={'Content':b'user,arn,mfa_active\nreviewer,arn:aws:iam::123456789012:user/reviewer,true\n', 'ReportFormat':'text/csv','GeneratedTime':datetime(2026,10,16,tzinfo=timezone.utc)}
    session=Mock();session.client.return_value=client
    requests=aws.Requests({})
    read=aws._credentials_report(requests,session,'us-east-1')
    assert read.status=='collected' and read.items[0]['mfa_active']=='true'
    client.get_credential_report.assert_called_once_with()
    client.generate_credential_report.assert_not_called()
    assert requests.calls==1 and requests.evidence_generations==0

@pytest.mark.parametrize('code',['ReportNotPresent','ReportExpired'])
def test_missing_existing_report_does_not_generate(code):
    from botocore.exceptions import ClientError
    client=Mock();client.get_credential_report.side_effect=ClientError({'Error':{'Code':code,'Message':'inert'}},'GetCredentialReport')
    session=Mock();session.client.return_value=client
    requests=aws.Requests({})
    read=aws._credentials_report(requests,session,'us-east-1')
    assert read.status=='not_collected' and not read.items
    assert read.error=={'code':'credential_report_generation_disabled','source_code':code}
    client.generate_credential_report.assert_not_called()
    assert requests.calls==1 and requests.evidence_generations==0

def test_usage_report_without_existing_job_is_unavailable_without_sdk():
    session=Mock();requests=aws.Requests({})
    arns=['arn:aws:iam::123456789012:role/a','arn:aws:iam::123456789012:user/b']
    result=aws._sla_reports(requests,session,'us-east-1',arns)
    assert set(result)==set(arns)
    assert all(rows is None and status['collection_status']=='not_collected' and status['error']['code']=='service_last_accessed_generation_disabled' for rows,status in result.values())
    session.client.assert_not_called()
    assert requests.calls==0
