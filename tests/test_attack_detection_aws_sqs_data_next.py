"""Accepted SQS data events from a scoped temporary CloudTrail trail."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_sqs_message_visibility_lab_events.json').read_text())
FIFO_EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_sqs_fifo_collision_lab_events.json').read_text())
RULE = Rule(id='test-sqs-message-hidden', title='SQS message hidden',
            description='SQS message visibility over one hour', level='medium',
            technique_id='aws-sqs-message-hidden-over-hour', product='aws',
            selection={'event.source': 'sqs.amazonaws.com',
                       'event.name': 'ChangeMessageVisibility',
                       'event.outcome': 'success',
                       'request.sqs_message_hidden_over_hour': True})
FIFO_RULE = Rule(id='test-sqs-fifo-collision', title='SQS FIFO collision',
                 description='Cross-actor FIFO deduplication collision', level='medium',
                 technique_id='aws-sqs-fifo-cross-actor-dedup-collision', product='aws',
                 selection={'event.name': 'SendMessage',
                            'request.sqs_fifo_cross_actor_dedup_collision': True})


def hits(events):
    return detect_aws_events(events, (RULE,))


def fifo_hits(events):
    return detect_aws_events(events, (FIFO_RULE,))


def test_real_long_visibility_and_short_timeout_controls():
    assert [hit.event_id for hit in hits(EVENTS)] == ['fcfac754-674f-4871-ab80-3699dad54e18']
    for event in EVENTS[1:]:
        assert not hits([event])


def test_requires_successful_scoped_sqs_data_event():
    event = next(e for e in EVENTS if e['requestParameters']['visibilityTimeout'] == 43100)
    for key, value in [('eventCategory', 'Management'), ('managementEvent', True),
                       ('readOnly', True), ('errorCode', 'AccessDenied')]:
        assert not hits([{**event, key: value}])
    for timeout in (False, '43100', -1, 43201):
        changed = copy.deepcopy(event)
        changed['requestParameters']['visibilityTimeout'] = timeout
        assert not hits([changed])
    changed = copy.deepcopy(event)
    changed['resources'][0]['ARN'] = changed['resources'][0]['ARN'].replace('standard', 'other')
    assert not hits([changed])


def test_real_cross_actor_fifo_collision_and_controls():
    pair = [e for e in FIFO_EVENTS if e['eventName'] == 'SendMessage'
            and e['requestParameters'].get('messageDeduplicationId', '').startswith('collision-')]
    assert len(pair) == 2
    assert len(fifo_hits(FIFO_EVENTS)) == 1
    assert fifo_hits(pair)[0].event_id in {e['eventID'] for e in pair}
    assert not fifo_hits([pair[0]])
    assert not fifo_hits([e for e in FIFO_EVENTS if e['eventName'] == 'SendMessageBatch'])
    altered = copy.deepcopy(pair)
    altered[1]['userIdentity']['arn'] = altered[0]['userIdentity']['arn']
    assert not fifo_hits(altered)
    altered = copy.deepcopy(pair)
    altered[1]['responseElements']['mD5OfMessageBody'] = altered[0]['responseElements']['mD5OfMessageBody']
    assert not fifo_hits(altered)
    altered = copy.deepcopy(pair)
    altered[1]['responseElements']['messageId'] = 'other-message-id'
    assert not fifo_hits(altered)
    altered = copy.deepcopy(pair)
    altered[1]['requestParameters']['messageGroupId'] = 'other-group'
    assert not fifo_hits(altered)
    altered = copy.deepcopy(pair)
    altered[1]['eventCategory'] = 'Management'
    assert not fifo_hits(altered)
    altered = copy.deepcopy(pair)
    altered[1]['errorCode'] = 'AccessDenied'
    assert not fifo_hits(altered)
