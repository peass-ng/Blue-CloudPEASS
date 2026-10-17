import copy
import importlib.util
from pathlib import Path
import pytest
import peaso.server.native_policy_validation as m
CID='azure|cis|multifactor_authentication_policy_exists_users'
GOOD={'status':'collected','scope':'/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','authorized_by':'security-owner','document_id':'mfa-policy','observed_at':'2026-10-01T00:00:00Z','expires_at':'2026-11-01T00:00:00Z','checks':{CID:{'userScope':'all','requiredApplications':['All'],'requiredClientAppTypes':['all']}}}
def test_accepts_only_normative_review_and_does_not_modify():
 p=copy.deepcopy(GOOD);m.azure_mfa_review(p);assert p==GOOD
@pytest.mark.parametrize('key,value',[('scope','/subscriptions/customer'),('scope','/tenants/'+'a'*36),('authorized_by',''),('document_id',False),('expires_at','bad'),('observed_at','2026-12-01T00:00:00Z'),('observed_at','2026-10-01'),('status','verified'),('endpoint','https://evil.test'),('native_proof',{'mfa':True})])
def test_rejects_foreign_or_unapproved_review(key,value):
 p=copy.deepcopy(GOOD);p[key]=value
 with pytest.raises(ValueError):m.azure_mfa_review(p)
@pytest.mark.parametrize('key,value',[('enforced',True),('userScope','everyone'),('requiredApplications',[]),('requiredClientAppTypes','all'),('riskLicensingConfirmed','true'),('designatedUsers',['same','same'])])
def test_rejects_observations_or_malformed_inner_review(key,value):
 p=copy.deepcopy(GOOD);p['checks'][CID][key]=value
 with pytest.raises(ValueError):m.azure_mfa_review(p)


import copy
import importlib.util
from pathlib import Path
import pytest
import peaso.server.native_policy_validation as m
GUEST_BASE={'status':'collected','scope':'/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','userRightsBaseline':{'name':'approved-baseline','version':'1.0.0','parameters':{'ExpectedUsers':'Administrators'},'maxAgeSeconds':3600}}
def test_exact_approved_baseline_roundtrip():
 p=copy.deepcopy(GUEST_BASE);m.azure_guest_baselines(p);assert p==GUEST_BASE
@pytest.mark.parametrize('field,value',[('enforced',True),('maxAgeSeconds',True),('maxAgeSeconds',0),('version',''),('parameters',{'key':{'compliant':True}})])
def test_invalid_baseline_facts_not_accepted(field,value):
 p=copy.deepcopy(GUEST_BASE);p['userRightsBaseline'][field]=value
 with pytest.raises(ValueError):m.azure_guest_baselines(p)
def test_time_source_approval_without_fabricating_measured_state():
 p=copy.deepcopy(GUEST_BASE);p['timeSyncBaseline']={**p['userRightsBaseline'],'measurementResourceId':'[TimeSync]ApprovedSource','measurementReasonCode':'ActualSource'};p['approvedTimeSourceIds']=['time.windows.com'];m.azure_guest_baselines(p)
 p['native_report']={'compliant':True}
 with pytest.raises(ValueError):m.azure_guest_baselines(p)


def test_new_review_namespaces_reach_the_actual_hosted_intake():
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    auth = {'method':'token','arm_token':'fixture'}
    for name, review in [('sw13', GOOD), ('sw18', GUEST_BASE)]:
        validate_connector('azure', auth, {'compliance_policy':{name:review}}, SimpleNamespace(auth_mode='cognito'))


@pytest.mark.parametrize('namespace,fields', [
    ('sw15', {'allowAzureServices': False}),
    ('sw25', {'checks': {'azure.cis.guest_users_reviewed_monthly_basis': {}}}),
    ('sw25', {'checks': {'azure.cis.guest_users_reviewed_regular_basis': {'maxReviewAgeDays': 90}}}),
])
def test_database_and_guest_reviews_reach_hosted_intake(namespace, fields):
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    review = {'status': 'collected', 'scope': GUEST_BASE['scope'], **fields}
    validate_connector('azure', {'method': 'token', 'arm_token': 'fixture'},
        {'compliance_policy': {namespace: review}}, SimpleNamespace(auth_mode='cognito'))


@pytest.mark.parametrize('namespace,fields', [
    ('sw15', {'allowAzureServices': 'false'}),
    ('sw15', {'allowAzureServices': False, 'native_proof': True}),
    ('sw25', {'checks': {'azure.cis.guest_users_reviewed_monthly_basis': {'completed': True}}}),
    ('sw25', {'checks': {'azure.cis.guest_users_reviewed_regular_basis': {'maxReviewAgeDays': True}}}),
    ('sw25', {'checks': {'azure.cis.guest_users_reviewed_regular_basis': {'maxReviewAgeDays': 0}}}),
    ('sw25', {'checks': {'azure.cis.guest_users_reviewed_regular_basis': {}}}),
    ('sw25', {'checks': {'foreign.id': {}}}),
])
def test_database_and_guest_reviews_reject_forged_or_malformed_intent(namespace, fields):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    review = {'status': 'collected', 'scope': GUEST_BASE['scope'], **fields}
    with pytest.raises(HTTPException) as error:
        validate_connector('azure', {'method': 'token', 'arm_token': 'fixture'},
            {'compliance_policy': {namespace: review}}, SimpleNamespace(auth_mode='cognito'))
    assert error.value.status_code == 422
