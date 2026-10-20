"""SQS management signals against accepted, sanitized CloudTrail events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_sqs_followup_management_events.json').read_text())
FIELDS = {'request.sqs_managed_sse_disabled', 'request.sqs_visibility_timeout_12h',
          'request.sqs_tag_activated_receive_grant'}
RULES = tuple(Rule(id=f, title=f, description=f, level='medium', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)


def hits(events):
    return {hit.technique_id for hit in detect_aws_events(events, RULES)}


def test_real_sqs_management_events_and_negative_controls():
    assert hits(EVENTS) == FIELDS
    policy = next(e for e in EVENTS if e['eventName'] == 'PutRolePolicy')
    tag = next(e for e in EVENTS if e['eventName'] == 'TagQueue')
    untag = next(e for e in EVENTS if e['eventName'] == 'UntagQueue')
    assert not hits([untag])
    assert not hits([tag])
    assert hits([tag, policy]) == {'request.sqs_tag_activated_receive_grant'}
    assert not hits([policy, {**tag, 'errorCode': 'AccessDenied'}])
    assert not hits([policy, {**tag, 'eventCategory': 'Data'}])
    altered = copy.deepcopy(tag)
    altered['requestParameters']['tags']['example-trust'] = 'false'
    assert not hits([policy, altered])
    altered_policy = copy.deepcopy(policy)
    document = json.loads(altered_policy['requestParameters']['policyDocument'])
    document['Statement'][0]['Resource'] = document['Statement'][0]['Resource'].replace(
        ':222233334444:', ':000000000000:')
    altered_policy['requestParameters']['policyDocument'] = json.dumps(document)
    assert not hits([altered_policy, tag])
    for event in (e for e in EVENTS if e['eventName'] == 'SetQueueAttributes'):
        assert not hits([{**event, 'errorCode': 'AccessDenied'}])
        assert not hits([{**event, 'readOnly': True}])
        assert not hits([{**event, 'recipientAccountId': '000000000000'}])
    encryption = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'SetQueueAttributes'
                                    and 'SqsManagedSseEnabled' in e['requestParameters']['attributes']))
    encryption['requestParameters']['attributes']['SqsManagedSseEnabled'] = 'true'
    assert not hits([encryption])
    visibility = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'SetQueueAttributes'
                                    and 'VisibilityTimeout' in e['requestParameters']['attributes']))
    visibility['requestParameters']['attributes']['VisibilityTimeout'] = '30'
    assert not hits([visibility])
