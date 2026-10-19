"""Cognito pool MFA update and app-client federation controls."""

import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT='222233334444'
POOL='us-east-1_AbCd1234'
FIELDS={'request.cognito_update_user_pool_mfa_off',
        'request.cognito_external_idp_enabled_on_client'}
RULES=tuple(Rule(id=field,title=field,description=field,level='high',
                 technique_id=field,product='aws',selection={field:True}) for field in FIELDS)


def event(name,request):
    return {'eventSource':'cognito-idp.amazonaws.com','eventName':name,
            'eventCategory':'Management','eventType':'AwsApiCall',
            'managementEvent':True,'readOnly':False,'recipientAccountId':ACCOUNT,
            'eventTime':'2026-10-19T16:10:00Z','eventID':name,
            'requestParameters':{'userPoolId':POOL,**request}}


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records,RULES)}


def test_pool_and_app_client_changes_with_negatives():
    pool=event('UpdateUserPool',{'mfaConfiguration':'OFF'})
    client=event('UpdateUserPoolClient',{'clientId':'abc',
                                         'supportedIdentityProviders':['COGNITO','Google']})
    assert hits([pool,client])==FIELDS
    assert hits([event('UpdateUserPool',{'mfaConfiguration':'ON'})])==set()
    assert hits([event('UpdateUserPoolClient',{'clientId':'abc',
                                              'supportedIdentityProviders':['COGNITO']})])==set()
    assert hits([{**client,'errorCode':'InvalidParameterException'}])==set()
    assert hits([{**pool,'eventCategory':'Data'}])==set()


def test_sanitized_real_cloudtrail_update_events():
    fixture=Path(__file__).parent/'fixtures'/'aws_cognito_update_lab_events.json'
    records=json.loads(fixture.read_text())
    assert hits(records)==FIELDS
    assert 'clientSecret' not in fixture.read_text()
