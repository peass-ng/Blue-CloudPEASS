"""ECS telemetry, task protection and dormant-service signals use real CloudTrail."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIELDS = {'request.ecs_container_insights_disabled', 'request.ecs_task_protection_enabled',
          'request.ecs_dormant_service_sidecar_activated'}
RULES = tuple(Rule(id=f, title=f, description=f, level='medium', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_ecs_lab_events.json').read_text())


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_real_ecs_controls_and_safe_negatives():
    assert hits(EVENTS) == FIELDS
    settings = next(e for e in EVENTS if e['eventName'] == 'UpdateClusterSettings')
    protect = next(e for e in EVENTS if e['eventName'] == 'UpdateTaskProtection'
                   and e['requestParameters']['protectionEnabled'])
    unprotect = next(e for e in EVENTS if e['eventName'] == 'UpdateTaskProtection'
                     and not e['requestParameters']['protectionEnabled'])
    assert hits([settings]) == {'request.ecs_container_insights_disabled'}
    assert hits([protect]) == {'request.ecs_task_protection_enabled'}
    assert not hits([unprotect])
    for event in (settings, protect):
        assert not hits([{**event, 'errorCode': 'AccessDenied'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
    failed_task = copy.deepcopy(protect)
    failed_task['responseElements']['failures'] = [{'arn': protect['requestParameters']['tasks'][0]}]
    assert not hits([failed_task])
    still_enabled = copy.deepcopy(settings)
    still_enabled['responseElements']['cluster']['settings'][0]['value'] = 'enabled'
    assert not hits([still_enabled])


def test_dormant_service_requires_added_container_and_prior_events():
    expected = {'request.ecs_dormant_service_sidecar_activated'}
    assert expected <= hits(EVENTS)
    assert not expected <= hits([e for e in EVENTS if e['eventName'] != 'CreateService'])
    assert not expected <= hits([e for e in EVENTS if e['eventName'] != 'RegisterTaskDefinition'])
    no_sidecar = copy.deepcopy(EVENTS)
    second = next(e for e in no_sidecar if e['eventName'] == 'RegisterTaskDefinition'
                  and e['responseElements']['taskDefinition']['revision'] == 2)
    second['requestParameters']['containerDefinitions'] = second['requestParameters']['containerDefinitions'][:1]
    assert not expected <= hits(no_sidecar)
    failed = copy.deepcopy(EVENTS)
    update = next(e for e in failed if e['eventName'] == 'UpdateService'
                  and e['requestParameters'].get('desiredCount') == 1)
    update['errorCode'] = 'AccessDeniedException'
    assert not expected <= hits(failed)
