"""SSM activation, automation, document and window detections on live CloudTrail."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_ssm_automation_activation_window_lab_events.json').read_text())
SPECS = [
    ('CreateActivation', 'ssm_hybrid_activation_created'),
    ('StartAutomationExecution', 'ssm_automation_started'),
    ('UpdateDocumentDefaultVersion', 'ssm_document_updated_and_default_promoted'),
    ('RegisterTaskWithMaintenanceWindow', 'ssm_window_target_then_command_task'),
]
RULES = tuple(Rule(id=f'test-{name}', title=name, description=name, level='low',
                   technique_id=f'test-{flag}', product='aws',
                   selection={'event.name': name, 'event.outcome': 'success', f'request.{flag}': True})
              for name, flag in SPECS)


def event(event_name, **request):
    result = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == event_name and not e.get('errorCode')))
    result['requestParameters'].update(request)
    return result


def hits(events):
    return detect_aws_events(events, RULES)


def test_live_events_activate_four_distinct_signals():
    assert {x.rule_id for x in hits(EVENTS)} == {r.id for r in RULES}
    assert not hits([e for e in EVENTS if e.get('errorCode')])


def test_activation_and_runbook_need_accepted_response():
    for name, response_id in [('CreateActivation', 'activationId'),
                              ('StartAutomationExecution', 'automationExecutionId')]:
        accepted = event(name)
        assert len(hits([accepted])) == 1
        bad = copy.deepcopy(accepted)
        bad['responseElements'].pop(response_id)
        assert not hits([bad])
        for key, value in [('errorCode', 'AccessDenied'), ('readOnly', True),
                           ('eventCategory', 'Data'), ('managementEvent', False)]:
            assert not hits([{**accepted, key: value}])


def test_document_promotion_requires_same_actor_document_and_success():
    updated, promoted = event('UpdateDocument'), event('UpdateDocumentDefaultVersion')
    assert not hits([promoted])
    assert len(hits([updated, promoted])) == 1
    for changed in [event('UpdateDocument', name='other-document'),
                    {**updated, 'errorCode': 'AccessDenied'},
                    {**updated, 'readOnly': True},
                    {**updated, 'userIdentity': {'arn': 'arn:aws:iam::222233334444:role/other'}}]:
        assert not hits([changed, promoted])
    assert not hits([updated, event('UpdateDocumentDefaultVersion', documentVersion='bad')])
    assert not hits([updated, event('UpdateDocumentDefaultVersion', documentVersion='3')])


def test_window_task_requires_matching_target_and_success():
    target, task = event('RegisterTargetWithMaintenanceWindow'), event('RegisterTaskWithMaintenanceWindow')
    assert not hits([task])
    assert len(hits([target, task])) == 1
    for changed in [event('RegisterTargetWithMaintenanceWindow', windowId='mw-00000000000000000'),
                    {**target, 'errorCode': 'AccessDenied'},
                    {**target, 'managementEvent': False}]:
        assert not hits([changed, task])
    assert not hits([target, event('RegisterTaskWithMaintenanceWindow', taskType='AUTOMATION')])
    changed = event('RegisterTaskWithMaintenanceWindow')
    changed['requestParameters']['targets'][0]['values'] = ['other-target']
    assert not hits([target, changed])
