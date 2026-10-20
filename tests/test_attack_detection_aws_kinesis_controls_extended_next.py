"""Kinesis control signals from real sanitized management events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIELDS = {
    'StopStreamEncryption': 'request.kinesis_encryption_stopped',
    'SplitShard': 'request.kinesis_shard_split',
    'MergeShards': 'request.kinesis_shards_merged',
    'UpdateStreamMode': 'request.kinesis_mode_on_demand',
}
RULES = [Rule(id=name, title=name, description=name, level='medium',
              technique_id=name, product='aws', selection={field: True})
         for name, field in FIELDS.items()]
EVENTS = json.loads((Path(__file__).parent / 'fixtures' /
                     'aws_kinesis_controls_extended_lab_events.json').read_text())


def hits(event):
    return {x.technique_id for x in detect_aws_events([event], RULES)}


def test_accepted_controls_and_contradictory_events():
    assert {next(iter(hits(x))) for x in EVENTS if hits(x)} == set(FIELDS)
    for event in EVENTS:
        name = event['eventName']
        assert hits(event) == ({name} if name in FIELDS else set())
        assert not hits({**event, 'errorCode': 'AccessDeniedException'})
        assert not hits({**event, 'eventCategory': 'Data'})
        assert not hits({**event, 'readOnly': True})
        assert not hits({**event, 'recipientAccountId': '000000000000',
                         'awsRegion': 'invalid-region'})
    split = next(x for x in EVENTS if x['eventName'] == 'SplitShard')
    bad = copy.deepcopy(split)
    bad['requestParameters']['newStartingHashKey'] = '0'
    assert not hits(bad)
    bad['requestParameters']['newStartingHashKey'] = '9' * 5000
    assert not hits(bad)
    merge = next(x for x in EVENTS if x['eventName'] == 'MergeShards')
    bad = copy.deepcopy(merge)
    bad['requestParameters']['adjacentShardToMerge'] = bad['requestParameters']['shardToMerge']
    assert not hits(bad)
    mode = next(x for x in EVENTS if x['eventName'] == 'UpdateStreamMode')
    bad = copy.deepcopy(mode)
    bad['requestParameters']['streamModeDetails']['streamMode'] = 'PROVISIONED'
    assert not hits(bad)
    bad = copy.deepcopy(mode)
    bad['requestParameters']['streamARN'] = bad['requestParameters']['streamARN'].replace(':222233334444:', ':000000000000:')
    assert not hits(bad)
