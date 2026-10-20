"""Correlate Glue session owners and statement callers across audit records."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = '222233334444'
CREATOR = f'arn:aws:iam::{ACCOUNT}:user/creator'
OTHER = f'arn:aws:sts::{ACCOUNT}:assumed-role/caller/lab'
RULE = Rule(id='cross-actor', title='cross actor', description='cross actor', level='high',
            technique_id='aws-glue-run-statement-existing-session', product='aws',
            selection={'event.source': 'glue.amazonaws.com', 'event.name': 'RunStatement',
                       'event.outcome': 'success', 'request.glue_cross_actor_session_statement': True})


def event(name, actor, request, when):
    return {'eventSource': 'glue.amazonaws.com', 'eventName': name,
            'eventCategory': 'Management', 'eventType': 'AwsApiCall',
            'managementEvent': True, 'readOnly': False, 'awsRegion': 'us-east-1',
            'recipientAccountId': ACCOUNT, 'userIdentity': {'accountId': ACCOUNT, 'arn': actor},
            'eventTime': when, 'requestParameters': request, 'eventID': name + when}


def test_cross_actor_correlation_works_in_reverse_arrival_order_and_requires_success():
    create = event('CreateSession', CREATOR, {'id': 'lab',
        'role': f'arn:aws:iam::{ACCOUNT}:role/glue-lab'}, '2026-10-19T15:00:00Z')
    run = event('RunStatement', OTHER, {'sessionId': 'lab'}, '2026-10-19T15:01:00Z')
    found = detect_aws_events(iter([run, create]), (RULE,))
    assert len(found) == 1
    assert found[0].actor_id == OTHER
    assert found[0].evidence['correlation']['creator_arn'] == CREATOR
    assert detect_aws_events([create, {**run, 'userIdentity': create['userIdentity']}], (RULE,)) == []
    assert detect_aws_events([{**create, 'errorCode': 'AccessDenied'}, run], (RULE,)) == []
    assert detect_aws_events([create, {**run, 'errorCode': 'AccessDenied'}], (RULE,)) == []
    assert detect_aws_events([run], (RULE,)) == []
    wrong_account = deepcopy(run)
    wrong_account['recipientAccountId'] = '111111111111'
    wrong_account['userIdentity']['accountId'] = '111111111111'
    assert detect_aws_events([create, wrong_account], (RULE,)) == []
