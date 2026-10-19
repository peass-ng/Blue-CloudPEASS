"""Cognito software MFA administrative changes."""

import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


POOL = 'us-east-1_AbCd1234'
ACCOUNT = '222233334444'
FIELDS = {'request.cognito_software_mfa_disabled', 'request.cognito_software_token_deleted'}
RULES = tuple(Rule(id=field, title=field, description=field, level='high',
                   technique_id=field, product='aws', selection={field: True}) for field in FIELDS)


def event(name, request):
    return {'eventSource': 'cognito-idp.amazonaws.com', 'eventName': name,
            'eventCategory': 'Management', 'eventType': 'AwsApiCall',
            'managementEvent': True, 'readOnly': False,
            'recipientAccountId': ACCOUNT, 'eventTime': '2026-10-19T15:50:00Z',
            'eventID': name, 'requestParameters': {'userPoolId': POOL, **request}}


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_mfa_disable_and_token_delete_with_negatives():
    disabled = event('AdminSetUserMFAPreference', {'softwareTokenMfaSettings': {'enabled': False}})
    deleted = event('AdminDeleteSoftwareToken', {})
    assert hits([disabled, deleted]) == FIELDS
    assert hits([event('AdminSetUserMFAPreference', {'softwareTokenMfaSettings': {'enabled': True}})]) == set()
    assert hits([{**deleted, 'errorCode': 'AccessDeniedException'}]) == set()
    assert hits([{**disabled, 'eventCategory': 'Data'}]) == set()


def test_sanitized_real_cloudtrail_mfa_events():
    fixture = Path(__file__).parent / 'fixtures' / 'aws_cognito_mfa_lab_events.json'
    records = json.loads(fixture.read_text())
    assert hits(records) == FIELDS
