"""Lambda role and access paths against sanitized management events from a live lab."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_lambda_privesc_batch_events.json').read_text())
FIELDS = {
    'request.lambda_execution_role_assigned': 'aws-lambda-execution-role-assigned',
    'request.lambda_role_assignment_followed_by_code_update': 'aws-lambda-role-assignment-then-code-update',
    'request.lambda_new_function_invoke_grant': 'aws-lambda-new-function-invoke-grant',
    'request.lambda_new_function_sqs_mapping': 'aws-lambda-new-function-sqs-mapping',
}
RULES = tuple(Rule(id=field, title=field, description=field, level='medium',
                   technique_id=technique, product='aws', selection={field: True})
              for field, technique in FIELDS.items())


def hits(events):
    return {(x.technique_id, x.event_id) for x in detect_aws_events(events, RULES)}


def event(name):
    return next(e for e in EVENTS if e['eventName'] == name)


def test_real_role_grant_code_and_mapping_sequence():
    assert hits(EVENTS) == {
        ('aws-lambda-execution-role-assigned', '5bae0421-bae4-4da8-b7e3-c267ed337fe0'),
        ('aws-lambda-role-assignment-then-code-update', 'c3cd2097-7c36-422e-83a7-c0119fd7a66a'),
        ('aws-lambda-new-function-invoke-grant', 'cc072699-d51c-49dd-934b-8524950e8b38'),
        ('aws-lambda-new-function-sqs-mapping', 'f1dde099-938f-4174-9442-959e15fe7a59'),
    }
    assert not hits([event('CreateFunction20150331')])
    assert not hits([event('UpdateFunctionCode20150331v2')])
    assert not hits([event('AddPermission20150331v2')])
    assert not hits([event('CreateEventSourceMapping20150331')])


def test_denied_mismatched_or_different_actor_events_do_not_correlate():
    created = event('CreateFunction20150331')
    role = event('UpdateFunctionConfiguration20150331v2')
    code = event('UpdateFunctionCode20150331v2')
    grant = event('AddPermission20150331v2')
    mapping = event('CreateEventSourceMapping20150331')
    assert not hits([{**role, 'errorCode': 'AccessDenied'}, code])
    assert not hits([{**role, 'eventCategory': 'Data'}, code])
    wrong_role = copy.deepcopy(role)
    wrong_role['responseElements']['role'] = created['requestParameters']['role']
    assert not hits([wrong_role, code])
    other_actor = copy.deepcopy(code)
    other_actor['userIdentity']['arn'] = 'arn:aws:sts::222233334444:assumed-role/other/session'
    assert not hits([role, other_actor]) - {
        ('aws-lambda-execution-role-assigned', '5bae0421-bae4-4da8-b7e3-c267ed337fe0')}
    wrong_grant = copy.deepcopy(grant)
    wrong_grant['requestParameters']['principal'] = 'arn:aws:iam::000000000000:role/other'
    assert not hits([created, wrong_grant])
    wrong_mapping = copy.deepcopy(mapping)
    wrong_mapping['responseElements']['eventSourceArn'] = 'arn:aws:sqs:us-east-1:000000000000:other'
    assert not hits([created, wrong_mapping])
    assert not hits([created, {**mapping, 'errorCode': 'AccessDenied'}])
