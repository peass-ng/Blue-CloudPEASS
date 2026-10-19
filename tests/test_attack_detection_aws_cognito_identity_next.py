"""Cognito identity-pool and confidential-client control changes."""

import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = '222233334444'
IDENTITY_POOL = 'us-east-1:7095efce-b854-465f-9564-9dbe17b21897'
USER_POOL = 'us-east-1_NmYUEbSR1'
ROLE = f'arn:aws:iam::{ACCOUNT}:role/lab'
CASES = (
    ('cognito-identity.amazonaws.com', 'SetIdentityPoolRoles',
     {'identityPoolId': IDENTITY_POOL, 'roles': {'authenticated': ROLE, 'unauthenticated': ROLE}},
     {'request.cognito_identity_auth_role_set', 'request.cognito_identity_guest_role_set'}),
    ('cognito-identity.amazonaws.com', 'UpdateIdentityPool',
     {'identityPoolId': IDENTITY_POOL, 'allowUnauthenticatedIdentities': True, 'allowClassicFlow': True},
     {'request.cognito_identity_guest_classic_enabled'}),
    ('cognito-identity.amazonaws.com', 'SetPrincipalTagAttributeMap',
     {'identityPoolId': IDENTITY_POOL, 'useDefaults': False, 'principalTags': {'dept': 'nickname'}},
     {'request.cognito_identity_mutable_principal_tag'}),
    ('cognito-idp.amazonaws.com', 'AddUserPoolClientSecret',
     {'userPoolId': USER_POOL, 'clientId': 'client'},
     {'request.cognito_user_pool_client_secret_added'}),
)
FIELDS = {field for *_, fields in CASES for field in fields}
RULES = tuple(Rule(id=field, title=field, description=field, level='high',
                   technique_id=field, product='aws', selection={field: True})
              for field in FIELDS)


def event(source, name, request):
    return {'eventSource': source, 'eventName': name, 'eventCategory': 'Management',
            'eventType': 'AwsApiCall', 'managementEvent': True, 'readOnly': False,
            'recipientAccountId': ACCOUNT, 'eventTime': '2026-10-19T15:39:00Z',
            'eventID': name, 'requestParameters': request,
            'userIdentity': {'arn': f'arn:aws:iam::{ACCOUNT}:user/lab'}}


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_identity_pool_changes_and_secret_addition():
    for source, name, request, expected in CASES:
        record = event(source, name, request)
        assert hits([record]) == expected
        assert hits([{**record, 'errorCode': 'AccessDeniedException'}]) == set()
        assert hits([{**record, 'eventCategory': 'Data'}]) == set()


def test_specific_conditions_are_required():
    benign = [
        event('cognito-identity.amazonaws.com', 'SetIdentityPoolRoles',
              {'identityPoolId': IDENTITY_POOL, 'roles': {}}),
        event('cognito-identity.amazonaws.com', 'UpdateIdentityPool',
              {'identityPoolId': IDENTITY_POOL, 'allowUnauthenticatedIdentities': False,
               'allowClassicFlow': True}),
        event('cognito-identity.amazonaws.com', 'SetPrincipalTagAttributeMap',
              {'identityPoolId': IDENTITY_POOL, 'useDefaults': False,
               'principalTags': {'dept': 'custom:dept'}}),
        event('cognito-idp.amazonaws.com', 'AddUserPoolClientSecret',
              {'userPoolId': USER_POOL}),
    ]
    assert hits(benign) == set()


def test_sanitized_real_cloudtrail_lab_events():
    fixture = Path(__file__).parent / 'fixtures' / 'aws_cognito_identity_lab_events.json'
    records = json.loads(fixture.read_text())
    assert len(records) == 5
    assert hits(records) == FIELDS
    assert 'clientSecretValue' not in fixture.read_text()
