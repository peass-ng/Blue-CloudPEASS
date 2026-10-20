"""Cognito account and external identity-provider management signals."""

import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = '222233334444'
POOL = 'us-east-1_AbCd1234'
CASES = (
    ('AdminConfirmSignUp', {}, 'request.cognito_admin_confirm_signup'),
    ('AdminUpdateUserAttributes', {}, 'request.cognito_admin_update_user_attributes'),
    ('AdminInitiateAuth', {'authFlow': 'ADMIN_USER_PASSWORD_AUTH', 'clientId': 'abc'},
     'request.cognito_admin_password_auth'),
    ('CreateIdentityProvider', {'providerName': 'Google', 'providerType': 'Google'},
     'request.cognito_external_idp_created'),
    ('UpdateIdentityProvider', {'providerName': 'Google', 'providerDetails': {'authorize_scopes': 'openid'}},
     'request.cognito_external_idp_updated'),
    ('AdminLinkProviderForUser', {'destinationUser': {'providerName': 'Cognito'},
                                  'sourceUser': {'providerName': 'Google'}},
     'request.cognito_external_identity_linked'),
)
FIELDS = {field for _, _, field in CASES}
RULES = tuple(Rule(id=field, title=field, description=field, level='medium',
                   technique_id=field, product='aws', selection={field: True}) for field in FIELDS)


def event(name, request):
    return {'eventSource': 'cognito-idp.amazonaws.com', 'eventName': name,
            'eventCategory': 'Management', 'eventType': 'AwsApiCall',
            'managementEvent': True, 'readOnly': False,
            'recipientAccountId': ACCOUNT, 'eventTime': '2026-10-19T15:45:00Z',
            'eventID': name, 'requestParameters': {'userPoolId': POOL, **request}}


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_management_signals_and_rejected_attempts():
    for name, request, field in CASES:
        record = event(name, request)
        assert hits([record]) == {field}
        assert hits([{**record, 'errorCode': 'AccessDeniedException'}]) == set()
        assert hits([{**record, 'eventCategory': 'Data'}]) == set()


def test_specific_auth_and_link_conditions():
    assert hits([event('AdminInitiateAuth', {'authFlow': 'ADMIN_NO_SRP_AUTH', 'clientId': 'abc'})]) == set()
    assert hits([event('AdminLinkProviderForUser', {'destinationUser': {'providerName': 'Cognito'},
                                                  'sourceUser': {'providerName': 'Cognito'}})]) == set()
    assert hits([event('UpdateIdentityProvider', {'providerName': 'Google'})]) == set()


def test_sanitized_real_cloudtrail_lab_events():
    fixture = Path(__file__).parent / 'fixtures' / 'aws_cognito_federation_lab_events.json'
    records = json.loads(fixture.read_text())
    assert hits(records) == FIELDS
    assert 'client_secret' not in fixture.read_text()
