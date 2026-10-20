"""Session Manager accepted start against a disposable managed EC2 node."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_ssm_managed_node_lab_events.json').read_text())
RULE = Rule(id='test-ssm-session-start', title='SSM session start',
            description='Accepted StartSession', level='medium',
            technique_id='aws-ssm-session-started', product='aws',
            selection={'event.name': 'StartSession', 'event.outcome': 'success',
                       'request.ssm_session_started': True})


def hits(events):
    return detect_aws_events(events, (RULE,))


def test_real_session_start_and_terminated_session_control():
    assert [x.event_id for x in hits(EVENTS)] == ['ccd79d63-bec6-43d8-980f-7652dc3fd24a']
    assert not hits([e for e in EVENTS if e['eventName'] == 'TerminateSession'])


def test_rejects_failed_or_incomplete_session_events():
    event = next(e for e in EVENTS if e['eventName'] == 'StartSession')
    for key, value in [('errorCode', 'AccessDenied'), ('readOnly', True),
                       ('eventCategory', 'Data'), ('managementEvent', False)]:
        assert not hits([{**event, key: value}])
    changed = copy.deepcopy(event)
    changed['requestParameters']['target'] = 'not-a-node'
    assert not hits([changed])
    changed = copy.deepcopy(event)
    changed['responseElements'].pop('sessionId')
    assert not hits([changed])
