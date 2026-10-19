"""A Glue run needs a nearby, successful script configuration for this signal."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = '222233334444'
ACTOR = f'arn:aws:iam::{ACCOUNT}:user/deployer'
ROLE = f'arn:aws:iam::{ACCOUNT}:role/glue-lab'
RULE = Rule(id='job-run', title='job run', description='job run', level='medium',
            technique_id='aws-glue-create-or-update-job-and-run', product='aws',
            selection={'event.source': 'glue.amazonaws.com', 'event.name': 'StartJobRun',
                       'event.outcome': 'success', 'request.glue_job_run_after_script_set': True})


def event(name, request, when):
    return {'eventSource': 'glue.amazonaws.com', 'eventName': name,
            'eventCategory': 'Management', 'eventType': 'AwsApiCall',
            'managementEvent': True, 'readOnly': False, 'awsRegion': 'us-east-1',
            'recipientAccountId': ACCOUNT, 'userIdentity': {'accountId': ACCOUNT, 'arn': ACTOR},
            'eventTime': when, 'requestParameters': request, 'eventID': name + when}


def test_create_update_and_run_correlate_but_unrelated_or_failed_do_not():
    created = event('CreateJob', {'name': 'lab', 'role': ROLE,
        'command': {'scriptLocation': 's3://canary/v1.py'}}, '2026-10-19T15:00:00Z')
    run1 = event('StartJobRun', {'jobName': 'lab'}, '2026-10-19T15:01:00Z')
    updated = event('UpdateJob', {'jobName': 'lab', 'jobUpdate': {'role': ROLE,
        'command': {'scriptLocation': 's3://canary/v2.py'}}}, '2026-10-19T15:02:00Z')
    run2 = event('StartJobRun', {'jobName': 'lab'}, '2026-10-19T15:03:00Z')
    found = detect_aws_events(reversed([created, run1, updated, run2]), (RULE,))
    assert len(found) == 2
    assert {x.evidence['correlation']['script_location'] for x in found} == {
        's3://canary/v1.py', 's3://canary/v2.py'}
    assert detect_aws_events([run1], (RULE,)) == []
    assert detect_aws_events([created, {**run1, 'errorCode': 'AccessDenied'}], (RULE,)) == []
    assert detect_aws_events([{**created, 'errorCode': 'AccessDenied'}, run1], (RULE,)) == []
    wrong_job = deepcopy(run1)
    wrong_job['requestParameters']['jobName'] = 'other'
    assert detect_aws_events([created, wrong_job], (RULE,)) == []
    late = deepcopy(run1)
    late['eventTime'] = '2026-10-19T15:31:00Z'
    assert detect_aws_events([created, late], (RULE,)) == []
