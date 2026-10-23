"""Synthetic derivative of a disposable SSM maintenance-window CloudTrail event."""

from copy import deepcopy

from peaso.attack_detection.aws_ssm_automation_window_next import normalize_aws_ssm_automation_window
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = '999999999999'
WINDOW = 'mw-aaaaaaaaaaaaaaaaa'
TASK = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
ROW = {
    'eventSource': 'ssm.amazonaws.com', 'eventName': 'UpdateMaintenanceWindowTask',
    'eventType': 'AwsApiCall', 'eventCategory': 'Management',
    'managementEvent': True, 'readOnly': False,
    'eventID': 'synthetic-b411-update', 'eventTime': '2026-10-22T23:50:00Z',
    'recipientAccountId': ACCOUNT, 'awsRegion': 'us-east-2',
    'userIdentity': {'type': 'IAMUser', 'accountId': ACCOUNT,
                     'arn': f'arn:aws:iam::{ACCOUNT}:user/synthetic-operator'},
    'requestParameters': {'windowId': WINDOW, 'windowTaskId': TASK},
    'responseElements': {
        'windowId': WINDOW, 'windowTaskId': TASK, 'taskArn': 'AWS-RunShellScript',
        'targets': [{'key': 'WindowTargetIds', 'values': ['synthetic-target']}],
    },
}
RULE = Rule(
    id='synthetic-b411-rule', title='Synthetic task update', description='Synthetic',
    level='medium', technique_id='aws-ssm-window-shell-task-updated', product='aws',
    selection={'event.source': 'ssm.amazonaws.com', 'event.name': 'UpdateMaintenanceWindowTask',
               'event.outcome': 'success', 'request.ssm_window_shell_task_updated': True},
)


def test_real_shape_derivative_detects_task_update_without_disclosing_identifiers():
    event = normalize_aws_ssm_automation_window(ROW)
    assert event is not None
    assert event['request.ssm_window_shell_task_updated'] is True
    assert event['target.id'].startswith('sha256:')
    assert WINDOW not in str(event) and TASK not in str(event)
    hits = detect_aws_events([ROW], (RULE,))
    assert len(hits) == 1
    assert hits[0].technique_id == 'aws-ssm-window-shell-task-updated'


def test_rejects_failed_wrong_task_or_foreign_actor():
    changes = (
        lambda row: row.update(errorCode='AccessDeniedException'),
        lambda row: row['responseElements'].update(taskArn='AWS-RunPowerShellScript'),
        lambda row: row['responseElements'].update(windowTaskId='ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee'),
        lambda row: row['responseElements'].update(targets=[]),
        lambda row: row['userIdentity'].update(accountId='888888888888'),
        lambda row: row.update(readOnly=True),
        lambda row: row.pop('eventID'),
    )
    for change in changes:
        row = deepcopy(ROW)
        change(row)
        assert normalize_aws_ssm_automation_window(row) is None
        assert detect_aws_events([row], (RULE,)) == []
