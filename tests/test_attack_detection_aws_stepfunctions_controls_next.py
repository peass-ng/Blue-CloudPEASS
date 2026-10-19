"""Step Functions controls tested against sanitized management events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events

EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_stepfunctions_controls_lab_events.json').read_text())
SPECS = [
    ('GetExecutionHistory', 'sfn_execution_history_data_read'),
    ('StopExecution', 'sfn_execution_stopped'),
    ('UpdateStateMachine', 'sfn_definition_updated'),
    ('DeleteStateMachine', 'sfn_machine_deleted'),
]
RULES = tuple(Rule(id=f'test-{name}', title=name, description=name, level='low',
                   technique_id=f'test-{flag}', product='aws',
                   selection={'event.name': name, 'event.outcome': 'success', f'request.{flag}': True})
              for name, flag in SPECS)


def hits(events):
    return detect_aws_events(events, RULES)


def event(name):
    return copy.deepcopy(next(e for e in EVENTS if e['eventName'] == name))


def test_live_events_hit_four_rules_and_normal_reads_do_not():
    assert {x.rule_id for x in hits(EVENTS)} == {r.id for r in RULES}
    assert not hits([e for e in EVENTS if e['eventName'] in ('DescribeStateMachine', 'DescribeExecution', 'StartExecution', 'TagResource', 'UntagResource')])


def test_rejects_errors_wrong_category_and_cross_account_arns():
    for name, _ in SPECS:
        positive = event(name)
        assert len(hits([positive])) == 1
        for key, value in [('errorCode', 'AccessDenied'), ('eventCategory', 'Data'),
                           ('managementEvent', False), ('readOnly', name != 'GetExecutionHistory')]:
            assert not hits([{**positive, key: value}])
        altered = copy.deepcopy(positive)
        arn_key = 'executionArn' if name in ('GetExecutionHistory', 'StopExecution') else 'stateMachineArn'
        altered['requestParameters'][arn_key] = altered['requestParameters'][arn_key].replace('222233334444', '000000000000')
        assert not hits([altered])


def test_operation_specific_evidence_is_required():
    history = event('GetExecutionHistory')
    history['requestParameters']['includeExecutionData'] = False
    assert not hits([history])
    stopped = event('StopExecution')
    stopped['responseElements'].pop('stopDate')
    assert not hits([stopped])
    updated = event('UpdateStateMachine')
    updated['requestParameters'].pop('definition')
    assert not hits([updated])
    updated = event('UpdateStateMachine')
    updated['responseElements'].pop('revisionId')
    assert not hits([updated])
