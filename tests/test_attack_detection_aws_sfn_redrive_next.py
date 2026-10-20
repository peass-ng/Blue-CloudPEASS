"""RedriveExecution on a failed synthetic SSM integration."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events

EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_sfn_redrive_lab_events.json').read_text())
RULE = Rule(id='test-redrive', title='Redrive', description='Accepted redrive', level='medium',
            technique_id='aws-sfn-execution-redriven', product='aws',
            selection={'event.name': 'RedriveExecution', 'event.outcome': 'success',
                       'request.sfn_execution_redriven': True})


def hits(events):
    return detect_aws_events(events, (RULE,))


def test_live_redrive_matches_but_initial_start_does_not():
    assert [x.event_id for x in hits(EVENTS)] == ['93308e2f-a254-4261-900d-3c47b8e73022']


def test_redrive_requires_accepted_own_execution_and_response():
    e = next(x for x in EVENTS if x['eventName'] == 'RedriveExecution')
    for key, value in [('errorCode', 'ExecutionNotRedrivable'), ('readOnly', True),
                       ('eventCategory', 'Data'), ('managementEvent', False)]:
        assert not hits([{**e, key: value}])
    altered = copy.deepcopy(e)
    altered['responseElements'].pop('redriveDate')
    assert not hits([altered])
    altered = copy.deepcopy(e)
    altered['requestParameters']['executionArn'] = altered['requestParameters']['executionArn'].replace('222233334444', '000000000000')
    assert not hits([altered])
