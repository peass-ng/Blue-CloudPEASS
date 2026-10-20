"""Outbound federation enablement and JWT issuance, using real redacted trail."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIELDS = {'request.sts_outbound_web_federation_enabled',
          'request.sts_web_identity_token_issued'}
RULES = tuple(Rule(id=f, title=f, description=f, level='low', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_sts_web_token_lab_events.json').read_text())


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_real_enable_and_token_events_but_not_failed_retry():
    assert hits(EVENTS) == FIELDS
    assert not hits([next(e for e in EVENTS if e.get('errorCode'))])
    assert 'WebIdentityToken":' not in json.dumps(EVENTS)


def test_missing_response_and_invalid_audience_are_negative():
    for event in EVENTS[:2]:
        assert not hits([{**event, 'responseElements': {}}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
    token = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'GetWebIdentityToken' and not e.get('errorCode')))
    token['requestParameters']['audience'] = []
    assert not hits([token])
