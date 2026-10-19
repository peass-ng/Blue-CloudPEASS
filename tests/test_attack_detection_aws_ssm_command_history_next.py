"""Run Command history to output-read correlation on sanitized live events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_ssm_managed_node_lab_events.json').read_text())
RULE = Rule(id='test-ssm-command-output', title='SSM command output read',
            description='Enumerated command output was read', level='low',
            technique_id='aws-ssm-command-output-read-after-enumeration', product='aws',
            selection={'event.name': 'GetCommandInvocation',
                       'request.ssm_command_output_read_after_enumeration': True})


def hits(events):
    return detect_aws_events(events, (RULE,))


def event(name):
    return next(e for e in EVENTS if e['eventName'] == name)


def test_real_enumeration_then_command_output_read():
    assert [x.event_id for x in hits(EVENTS)] == ['222a00ac-7c59-44cd-96ae-5a9198d85a22']
    get = event('GetCommandInvocation')
    listed = event('ListCommands')
    invocations = event('ListCommandInvocations')
    assert not hits([get])
    assert len(hits([listed, get])) == 1
    assert len(hits([invocations, get])) == 1


def test_denied_mismatched_or_unrelated_reads_do_not_match():
    get = event('GetCommandInvocation')
    listed = event('ListCommands')
    assert not hits([{**listed, 'errorCode': 'AccessDenied'}, get])
    assert not hits([listed, {**get, 'errorCode': 'AccessDenied'}])
    assert not hits([{**listed, 'readOnly': False}, get])
    altered = copy.deepcopy(get)
    altered['userIdentity']['arn'] = 'arn:aws:sts::222233334444:assumed-role/other/session'
    assert not hits([listed, altered])
    altered = copy.deepcopy(get)
    altered['requestParameters']['commandId'] = '00000000-0000-4000-8000-000000000000'
    assert not hits([listed, altered])
    altered = copy.deepcopy(get)
    altered['eventTime'] = '2026-10-19T19:46:21Z'
    assert not hits([listed, altered])
    altered = copy.deepcopy(get)
    altered['requestParameters']['instanceId'] = 'not-a-node'
    assert not hits([listed, altered])
