"""Cognito user import management events."""

import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = '222233334444'
POOL = 'us-east-1_AbCd1234'
ROLE = f'arn:aws:iam::{ACCOUNT}:role/import'
FIELDS = {'request.cognito_import_job_created', 'request.cognito_import_job_started'}
RULES = tuple(Rule(id=field, title=field, description=field, level='medium',
                   technique_id=field, product='aws', selection={field: True}) for field in FIELDS)


def event(name, request):
    return {'eventSource': 'cognito-idp.amazonaws.com', 'eventName': name,
            'eventCategory': 'Management', 'eventType': 'AwsApiCall',
            'managementEvent': True, 'readOnly': False,
            'recipientAccountId': ACCOUNT, 'eventTime': '2026-10-19T16:00:00Z',
            'eventID': name, 'requestParameters': {'userPoolId': POOL, **request}}


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_import_create_start_and_negatives():
    created = event('CreateUserImportJob', {'jobName': 'canary', 'cloudWatchLogsRoleArn': ROLE})
    started = event('StartUserImportJob', {'jobId': 'import-canary'})
    assert hits([created, started]) == FIELDS
    assert hits([{**created, 'errorCode': 'InvalidParameterException'}]) == set()
    assert hits([{**started, 'eventCategory': 'Data'}]) == set()
    assert hits([event('CreateUserImportJob', {'jobName': 'canary'})]) == set()
    assert hits([event('StartUserImportJob', {})]) == set()


def test_sanitized_real_cloudtrail_import_events():
    fixture = Path(__file__).parent / 'fixtures' / 'aws_cognito_import_lab_events.json'
    records = json.loads(fixture.read_text())
    assert hits(records) == FIELDS
    assert 'preSignedUrl' not in fixture.read_text()
