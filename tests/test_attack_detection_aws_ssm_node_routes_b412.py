"""Synthetic derivatives of disposable SSM node and session events."""

from copy import deepcopy

from peaso.attack_detection.aws_ssm_node_routes_b412 import (
    correlate_cross_principal_resume, normalize_shell_command,
)
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = '999999999999'
NODE = 'i-aaaaaaaaaaaaaaaaa'
SESSION = 'synthetic-user-aaaaaaaaaaaaaaaa'
START_ACTOR = f'arn:aws:iam::{ACCOUNT}:user/synthetic-operator'
RESUME_ACTOR = f'arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-resumer/session'
COMMON = {
    'eventSource': 'ssm.amazonaws.com', 'eventType': 'AwsApiCall',
    'eventCategory': 'Management', 'managementEvent': True, 'readOnly': False,
    'recipientAccountId': ACCOUNT, 'awsRegion': 'us-east-2',
}
SEND = {
    **COMMON, 'eventName': 'SendCommand', 'eventID': 'synthetic-command-event',
    'eventTime': '2026-10-23T00:00:00Z',
    'userIdentity': {'type': 'AssumedRole', 'accountId': ACCOUNT,
                     'arn': f'arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-sender/session'},
    'requestParameters': {'documentName': 'AWS-RunShellScript', 'instanceIds': [NODE],
                          'parameters': 'HIDDEN_DUE_TO_SECURITY_REASONS'},
    'responseElements': {'command': {'commandId': 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
                                     'documentName': 'AWS-RunShellScript',
                                     'instanceIds': [NODE],
                                     'parameters': 'HIDDEN_DUE_TO_SECURITY_REASONS'}},
}
START = {
    **COMMON, 'eventName': 'StartSession', 'eventID': 'synthetic-start-event',
    'eventTime': '2026-10-23T00:01:00Z',
    'userIdentity': {'type': 'IAMUser', 'accountId': ACCOUNT, 'arn': START_ACTOR},
    'requestParameters': {'target': NODE},
    'responseElements': {'sessionId': SESSION,
                         'tokenValue': 'HIDDEN_DUE_TO_SECURITY_REASONS'},
}
RESUME = {
    **COMMON, 'eventName': 'ResumeSession', 'eventID': 'synthetic-resume-event',
    'eventTime': '2026-10-23T00:02:00Z',
    'userIdentity': {'type': 'AssumedRole', 'accountId': ACCOUNT, 'arn': RESUME_ACTOR},
    'requestParameters': {'sessionId': SESSION},
    'responseElements': {'sessionId': SESSION,
                         'tokenValue': 'HIDDEN_DUE_TO_SECURITY_REASONS'},
}
RULES = (
    Rule(id='synthetic-shell', title='Synthetic shell', description='Synthetic',
         level='medium', technique_id='aws-ssm-shell-command-sent', product='aws',
         selection={'event.source': 'ssm.amazonaws.com', 'event.name': 'SendCommand',
                    'event.outcome': 'success', 'request.ssm_shell_command_sent': True}),
    Rule(id='synthetic-resume', title='Synthetic resume', description='Synthetic',
         level='high', technique_id='aws-ssm-cross-principal-session-resumed', product='aws',
         selection={'event.source': 'ssm.amazonaws.com', 'event.name': 'ResumeSession',
                    'event.outcome': 'success',
                    'request.ssm_session_resumed_by_other_principal': True}),
)


def test_shell_command_and_other_principal_resume_hit_without_raw_targets():
    shell = normalize_shell_command(SEND)
    assert shell is not None and shell['request.ssm_shell_command_sent'] is True
    resume = correlate_cross_principal_resume([START, RESUME])
    assert len(resume) == 1
    hits = detect_aws_events([SEND, START, RESUME], RULES)
    assert {hit.technique_id for hit in hits} == {
        'aws-ssm-shell-command-sent', 'aws-ssm-cross-principal-session-resumed'}
    assert all(hit.target_id.startswith('sha256:') for hit in hits)
    assert NODE not in str(hits) and SESSION not in str(hits)


def test_shell_command_rejects_failed_or_incoherent_events():
    changes = (
        lambda row: row.update(errorCode='AccessDeniedException'),
        lambda row: row['userIdentity'].update(accountId='888888888888'),
        lambda row: row['responseElements']['command'].update(instanceIds=['i-bbbbbbbbbbbbbbbbb']),
        lambda row: row['requestParameters'].update(documentName='AWS-RunPowerShellScript'),
        lambda row: row['requestParameters'].update(instanceIds=['invalid-node']),
        lambda row: row['responseElements']['command'].update(commandId='invalid'),
        lambda row: row.update(readOnly=True),
    )
    for change in changes:
        row = deepcopy(SEND)
        change(row)
        assert normalize_shell_command(row) is None
        assert detect_aws_events([row], RULES) == []


def test_resume_requires_same_session_and_distinct_same_account_principal():
    changes = (
        lambda row: row['userIdentity'].update(arn=START_ACTOR),
        lambda row: row['userIdentity'].update(accountId='888888888888'),
        lambda row: row['responseElements'].update(sessionId='different-session'),
        lambda row: row.update(errorCode='AccessDeniedException'),
        lambda row: row.update(eventTime='2026-10-24T00:01:01Z'),
        lambda row: row.update(eventTime='2026-10-23T00:00:59Z'),
    )
    for change in changes:
        row = deepcopy(RESUME)
        change(row)
        assert correlate_cross_principal_resume([START, row]) == []
        assert detect_aws_events([START, row], RULES) == []
    assert correlate_cross_principal_resume([RESUME]) == []
