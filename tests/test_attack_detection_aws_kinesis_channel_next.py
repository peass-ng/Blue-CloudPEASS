"""Kinesis S3 channel creation from a sanitized CloudTrail event."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id='kinesis-s3-channel', title='kinesis-s3-channel',
            description='kinesis-s3-channel', level='medium',
            technique_id='aws-kinesis-s3-channel-created', product='aws',
            selection={'request.kinesis_s3_channel_created': True})
EVENT = json.loads((Path(__file__).parent / 'fixtures' /
                    'aws_kinesis_channel_lab_event.json').read_text())


def hits(event):
    return detect_aws_events([event], [RULE])


def test_accepted_channel_and_contradictions():
    assert [x.technique_id for x in hits(EVENT)] == [RULE.technique_id]
    for change in (
        {'errorCode': 'AccessDeniedException'},
        {'eventCategory': 'Data'},
        {'readOnly': True},
        {'managementEvent': False},
    ):
        assert not hits({**EVENT, **change})
    for path, replacement in (
        (('requestParameters', 'streamConfigurationList', 0, 'streamARN'), 'arn:aws:kinesis:us-east-1:000000000000:stream/other'),
        (('requestParameters', 'serviceExecutionRoleARN'), 'arn:aws:iam::000000000000:role/other'),
        (('requestParameters', 's3DestinationConfiguration', 'storageConfiguration', 'bucketARN'), 'arn:aws:s3:::other-bucket'),
        (('responseElements', 'channelDescription', 'channelStatus'), 'FAILED'),
        (('responseElements', 'channelDescription', 'channelARN'), 'arn:aws:kinesis:us-east-1:222233334444:channel/other'),
    ):
        bad = copy.deepcopy(EVENT)
        target = bad
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = replacement
        assert not hits(bad)
