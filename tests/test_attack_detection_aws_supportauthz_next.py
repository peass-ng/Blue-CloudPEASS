"""Support permits require accepted, broad, open-ended authorization."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id='support-open', title='Support open permit', description='Support open permit',
            level='high', technique_id='aws-supportauthz-broad-open-permit', product='aws',
            selection={'request.support_permit_broad_open_ended': True})


def hits(records):
    return detect_aws_events(records, (RULE,))


def test_real_broad_permit_and_negative_variants():
    fixture = Path(__file__).parent / 'fixtures' / 'aws_supportauthz_lab_events.json'
    events = json.loads(fixture.read_text())
    assert len(hits(events)) == 1
    event = next(e for e in events if e['eventName'] == 'CreateSupportPermit')
    for mutation in (
        lambda e: e.update(errorCode='AccessDeniedException'),
        lambda e: e.update(eventCategory='Data'),
        lambda e: e['requestParameters']['permit']['actions'].clear(),
        lambda e: e['requestParameters']['permit']['resources'].clear(),
        lambda e: e['requestParameters'].update(supportCaseDisplayId='123456789'),
        lambda e: e['requestParameters']['permit'].update(conditions=[{'allowBefore': 10000000000}]),
        lambda e: e['responseElements'].update(status='INACTIVE'),
        lambda e: e['responseElements'].update(arn='arn:aws:supportauthz:us-east-1:000000000000:supportpermit/other'),
    ):
        trial = copy.deepcopy(event)
        mutation(trial)
        assert not hits([trial])
