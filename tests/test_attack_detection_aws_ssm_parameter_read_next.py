"""SSM Parameter Store read signals against real, sanitized CloudTrail events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_ssm_parameter_read_lab_events.json').read_text())
FIELDS = {'request.ssm_parameter_history_decrypted',
          'request.ssm_parameter_path_recursive_decrypted'}
RULES = tuple(Rule(id=f, title=f, description=f, level='medium', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)


def hits(events):
    return {hit.technique_id for hit in detect_aws_events(events, RULES)}


def test_real_decrypted_parameter_reads_and_negative_controls():
    assert hits(EVENTS) == FIELDS
    assert not hits([e for e in EVENTS if e['eventName'] == 'GetParameter'])
    for event in (e for e in EVENTS if e['eventName'] in ('GetParameterHistory', 'GetParametersByPath')):
        assert not hits([{**event, 'errorCode': 'AccessDeniedException'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
        assert not hits([{**event, 'readOnly': False}])
        unchanged = copy.deepcopy(event)
        unchanged['requestParameters']['withDecryption'] = False
        assert not hits([unchanged])
    path = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'GetParametersByPath'))
    path['requestParameters']['recursive'] = False
    assert not hits([path])
