"""Explicit function environments never expand account, Region or version scope."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import OPTIONS,validate_connector
SCOPE='123456789012/us-east-1'
ARN='arn:aws:lambda:us-east-1:123456789012:function:review'
def validate(targets,scopes=None,provider='aws'):
    validate_connector(provider,{}, {'selected_aws_lambda_functions':targets,'content_secret_scans':True},
                       SimpleNamespace(auth_mode='local'),scopes=[SCOPE]if scopes is None else scopes)
def test_exact_unqualified_scope_target_needs_no_credential_read():
    assert 'selected_aws_lambda_functions'in OPTIONS
    validate([ARN])
@pytest.mark.parametrize('fault',['empty','none','string','duplicate','foreign_account','foreign_region','version','alias','wildcard','url','many','missing_scopes','account_only','wrong_provider'])
def test_invalid_optional_environment_selection_fails_before_authentication(fault):
    targets,scopes,provider=[ARN],[SCOPE],'aws'
    if fault=='empty':targets=[]
    elif fault=='none':targets=None
    elif fault=='string':targets=ARN
    elif fault=='duplicate':targets*=2
    elif fault=='foreign_account':targets=[ARN.replace('123456789012','210987654321')]
    elif fault=='foreign_region':targets=[ARN.replace('us-east-1','eu-west-1')]
    elif fault in ('version','alias'):targets=[ARN+(':'+('1'if fault=='version'else'live'))]
    elif fault=='wildcard':targets=[ARN+'*']
    elif fault=='url':targets=['https://lambda.amazonaws.com/'+ARN]
    elif fault=='many':targets=[ARN+str(i)for i in range(9)]
    elif fault=='missing_scopes':scopes=[]
    elif fault=='account_only':scopes=['123456789012']
    elif fault=='wrong_provider':provider='gcp'
    with pytest.raises(HTTPException)as error:validate(targets,scopes,provider)
    assert error.value.status_code==422
