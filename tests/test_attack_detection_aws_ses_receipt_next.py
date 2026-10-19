"""SES receipt routing detections use sanitized real CloudTrail events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIELDS = {'request.ses_receipt_s3_catchall', 'request.ses_receipt_scan_disabled',
          'request.ses_receipt_rule_set_activated'}
RULES = tuple(Rule(id=f, title=f, description=f, level='medium', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_ses_receipt_lab_events.json').read_text())


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_real_receipt_routing_and_negative_controls():
    create = next(e for e in EVENTS if e['eventName'] == 'CreateReceiptRule')
    update = next(e for e in EVENTS if e['eventName'] == 'UpdateReceiptRule')
    active = next(e for e in EVENTS if e['eventName'] == 'SetActiveReceiptRuleSet' and e.get('requestParameters'))
    restore = next(e for e in EVENTS if e['eventName'] == 'SetActiveReceiptRuleSet' and not e.get('requestParameters'))
    assert hits([create]) == {'request.ses_receipt_s3_catchall', 'request.ses_receipt_scan_disabled'}
    assert hits([update]) == {'request.ses_receipt_s3_catchall'}
    assert hits([active]) == {'request.ses_receipt_rule_set_activated'}
    assert not hits([restore])
    assert not hits([next(e for e in EVENTS if e['eventName'] == 'DeleteReceiptRuleSet')])
    for event in (create, update, active):
        assert not hits([{**event, 'errorCode': 'AccessDenied'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
        assert not hits([{**event, 'readOnly': True}])
    targeted = copy.deepcopy(create)
    targeted['requestParameters']['rule']['recipients'] = ['canary.example.invalid']
    assert 'request.ses_receipt_s3_catchall' not in hits([targeted])
    disabled = copy.deepcopy(create)
    disabled['requestParameters']['rule']['enabled'] = False
    assert not hits([disabled])
    no_s3 = copy.deepcopy(create)
    no_s3['requestParameters']['rule']['actions'] = [{'stopAction': {'scope': 'RuleSet'}}]
    assert 'request.ses_receipt_s3_catchall' not in hits([no_s3])
