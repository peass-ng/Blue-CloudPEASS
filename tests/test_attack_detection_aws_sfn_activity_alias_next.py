"""Activity callback and alias/version events from disposable live workflows."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events

EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_sfn_activity_alias_lab_events.json').read_text())
SPECS = [
    ('SendTaskSuccess', 'sfn_activity_callback_success'),
    ('UpdateStateMachineAlias', 'sfn_alias_routed_to_version'),
    ('DeleteStateMachineAlias', 'sfn_alias_deleted'),
    ('DeleteStateMachineVersion', 'sfn_version_deleted'),
]
RULES = tuple(Rule(id=f'test-{name}', title=name, description=name, level='low',
                   technique_id=f'test-{flag}', product='aws',
                   selection={'event.name': name, 'event.outcome': 'success', f'request.{flag}': True})
              for name, flag in SPECS)


def event(name):
    return copy.deepcopy(next(e for e in EVENTS if e['eventName'] == name))


def hits(events):
    return detect_aws_events(events, RULES)


def test_live_callbacks_alias_switch_and_deletions():
    assert len(hits(EVENTS)) == 5
    assert {x.rule_id for x in hits(EVENTS)} == {r.id for r in RULES}
    assert not hits([e for e in EVENTS if e['eventName'] in ('CreateActivity', 'CreateStateMachineAlias', 'StartExecution')])


def test_rejects_errors_wrong_event_class_and_missing_callback_evidence():
    for name, _ in SPECS:
        positive = event(name)
        assert len(hits([positive])) == 1
        for key, value in [('errorCode', 'AccessDenied'), ('eventCategory', 'Data'),
                           ('managementEvent', False), ('readOnly', True)]:
            assert not hits([{**positive, key: value}])
    callback = event('SendTaskSuccess')
    callback['requestParameters']['taskToken'] = ''
    assert not hits([callback])
    callback = event('SendTaskSuccess')
    callback['requestParameters'].pop('output')
    assert not hits([callback])


def test_alias_switch_requires_same_machine_version_and_full_weight():
    update = event('UpdateStateMachineAlias')
    update['requestParameters']['routingConfiguration'][0]['weight'] = 50
    assert not hits([update])
    update = event('UpdateStateMachineAlias')
    update['requestParameters']['routingConfiguration'][0]['stateMachineVersionArn'] = update['requestParameters']['routingConfiguration'][0]['stateMachineVersionArn'].replace('-version:2', '-other:2')
    assert not hits([update])
    update = event('UpdateStateMachineAlias')
    update['responseElements'].pop('updateDate')
    assert not hits([update])


def test_alias_and_version_deletions_require_own_account_arn():
    for name, key in [('DeleteStateMachineAlias', 'stateMachineAliasArn'),
                      ('DeleteStateMachineVersion', 'stateMachineVersionArn')]:
        changed = event(name)
        changed['requestParameters'][key] = changed['requestParameters'][key].replace('222233334444', '000000000000')
        assert not hits([changed])
