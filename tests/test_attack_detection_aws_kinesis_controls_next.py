"""Kinesis control detections use accepted, sanitized CloudTrail events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIELDS = {'request.kinesis_retention_decreased', 'request.kinesis_monitoring_disabled',
          'request.kinesis_stream_policy_changed', 'request.kinesis_consumer_subscription_granted',
          'request.kinesis_consumer_registered', 'request.kinesis_stream_deleted',
          'request.kinesis_shard_count_changed', 'request.kinesis_record_limit_raised'}
RULES = tuple(Rule(id=f, title=f, description=f, level='medium', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_kinesis_lab_events.json').read_text())
CAPACITY_EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_kinesis_capacity_lab_events.json').read_text())


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_real_control_writes_and_negative_controls():
    assert hits(EVENTS) == FIELDS - {'request.kinesis_shard_count_changed', 'request.kinesis_record_limit_raised'}
    positive = [e for e in EVENTS if hits([e])]
    assert len(positive) == 6  # two policies and four other control writes
    for event in positive:
        assert len(hits([event])) == 1
        assert not hits([{**event, 'errorCode': 'AccessDeniedException'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
        assert not hits([{**event, 'readOnly': True}])
    for event in EVENTS:
        if event not in positive:
            assert not hits([event])
    stream_policy = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'PutResourcePolicy'
                                       and '/consumer/' not in e['requestParameters']['resourceARN']))
    stream_policy['requestParameters']['resourceARN'] = stream_policy['requestParameters']['resourceARN'].replace(
        ':222233334444:', ':000000000000:')
    assert not hits([stream_policy])
    consumer = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'PutResourcePolicy'
                                  and '/consumer/' in e['requestParameters']['resourceARN']))
    policy = json.loads(consumer['requestParameters']['policy'])
    policy['Statement'][0]['Action'] = ['kinesis:DescribeStreamConsumer']
    consumer['requestParameters']['policy'] = json.dumps(policy)
    assert not hits([consumer])


def test_real_capacity_changes_and_negative_controls():
    assert hits(CAPACITY_EVENTS) == {'request.kinesis_shard_count_changed',
                                     'request.kinesis_record_limit_raised'}
    shard = next(e for e in CAPACITY_EVENTS if e['eventName'] == 'UpdateShardCount')
    size = next(e for e in CAPACITY_EVENTS if e['eventName'] == 'UpdateMaxRecordSize')
    for event in (shard, size):
        assert not hits([{**event, 'errorCode': 'ResourceInUseException'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
    unchanged = copy.deepcopy(shard)
    unchanged['responseElements']['currentShardCount'] = unchanged['requestParameters']['targetShardCount']
    assert not hits([unchanged])
    normal = copy.deepcopy(size)
    normal['requestParameters']['maxRecordSizeInKiB'] = 1024
    assert not hits([normal])
