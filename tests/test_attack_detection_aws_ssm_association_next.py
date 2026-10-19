"""SSM association execution and current parameter reads from real CloudTrail."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIXTURES = Path(__file__).parent / 'fixtures'
EVENTS = json.loads((FIXTURES / 'aws_ssm_association_command_lab_events.json').read_text())
OLDER_READS = json.loads((FIXTURES / 'aws_ssm_parameter_read_lab_events.json').read_text())
START = Rule(id='test-start', title='Start association', description='One-time start',
             level='medium', technique_id='aws-ssm-association-started-once',
             product='aws', selection={'event.name': 'StartAssociationsOnce',
                                       'event.outcome': 'success',
                                       'request.ssm_association_started_once': True})
READ = Rule(id='test-read', title='Read current parameter', description='Decrypted read',
            level='low', technique_id='aws-ssm-parameter-current-decrypted',
            product='aws', selection={'event.name': ['GetParameter', 'GetParameters'],
                                      'event.outcome': 'success',
                                      'request.ssm_parameter_current_decrypted': True})


def hits(events, rule):
    return detect_aws_events(events, (rule,))


def test_accepted_one_time_start_and_controls():
    found = hits(EVENTS, START)
    assert [x.event_id for x in found] == ['3e8a6e84-cb8a-4f65-9f55-b559bc4b52c0']
    event = next(e for e in EVENTS if e['eventName'] == 'StartAssociationsOnce')
    for key, value in [('errorCode', 'AccessDenied'), ('eventCategory', 'Data'),
                       ('readOnly', True), ('managementEvent', False)]:
        assert not hits([{**event, key: value}], START)
    changed = copy.deepcopy(event)
    changed['requestParameters']['associationIds'] = []
    assert not hits([changed], START)
    changed['requestParameters']['associationIds'] = ['not-an-association']
    assert not hits([changed], START)
    assert not hits([e for e in EVENTS if e['eventName'] == 'SendCommand'], START)


def test_decrypted_current_parameter_read_and_plain_controls():
    assert [x.event_id for x in hits(OLDER_READS, READ)] == ['faa25711-85a8-48fe-8638-2c81b13413c4']
    assert [x.event_id for x in hits(EVENTS, READ)] == ['652e2448-0190-48a6-acf8-02c18684f840']
    assert not hits([e for e in EVENTS if e['eventName'] == 'GetParameters'
                     and not e['requestParameters'].get('withDecryption')], READ)
    event = next(e for e in OLDER_READS if e['eventID'] == 'faa25711-85a8-48fe-8638-2c81b13413c4')
    for key, value in [('errorCode', 'AccessDenied'), ('readOnly', False),
                       ('eventCategory', 'Data')]:
        assert not hits([{**event, key: value}], READ)
    changed = copy.deepcopy(event)
    changed['requestParameters']['withDecryption'] = False
    assert not hits([changed], READ)
