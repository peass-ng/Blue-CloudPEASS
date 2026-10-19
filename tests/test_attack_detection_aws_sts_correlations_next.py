"""STS role cycles require two linked successful CloudTrail calls."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id='sts-cycle', title='STS cycle', description='STS cycle', level='medium',
            technique_id='aws-sts-role-chain-juggling-cycle', product='aws',
            selection={'request.sts_role_cycle': True})
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_sts_role_cycle_lab_events.json').read_text())


def hits(events):
    return detect_aws_events(events, (RULE,))


def test_real_linked_role_cycle():
    result = hits(EVENTS)
    assert len(result) == 1
    assert result[0].event_id == 'a52efdd8-e5f6-41d6-88b4-09aa32ccd6f0'
    assert result[0].evidence['correlation']['first_event_id'] == '0323b415-f293-42ed-b0f5-51cb38fb69f8'
    assert 'sessionToken' not in json.dumps(EVENTS)


def test_unlinked_failed_and_cross_account_calls_are_negative():
    assert not hits(EVENTS[:1])
    assert not hits(EVENTS[1:])
    for mutation in (
        lambda records: records[1].update(errorCode='AccessDenied'),
        lambda records: records[1]['userIdentity'].update(arn='arn:aws:sts::222233334444:assumed-role/other/session'),
        lambda records: records[1]['requestParameters'].update(roleArn='arn:aws:iam::222233334444:role/other'),
        lambda records: records[1].update(recipientAccountId='000000000000'),
        lambda records: records[1].update(eventTime='2026-10-19T17:18:06Z'),
        lambda records: records[0].update(eventCategory='Data'),
    ):
        records = copy.deepcopy(EVENTS)
        mutation(records)
        assert not hits(records)
