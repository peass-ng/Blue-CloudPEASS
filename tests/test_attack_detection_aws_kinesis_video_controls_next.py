"""Kinesis Video control rules against accepted, sanitized CloudTrail events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_kinesis_video_lab_events.json').read_text())
FIELDS = {
    'request.kvs_media_storage_mapped', 'request.kvs_media_storage_disabled',
    'request.kvs_notification_destination_enabled', 'request.kvs_notification_disabled',
    'request.kvs_image_generation_destination_enabled', 'request.kvs_image_generation_disabled',
    'request.kvs_retention_decreased', 'request.kvs_stream_configuration_updated',
    'request.kvs_stream_deleted', 'request.kvs_signaling_channel_deleted',
}
RULES = tuple(Rule(id=field, title=field, description=field, level='medium',
                   technique_id=field, product='aws', selection={field: True}) for field in FIELDS)


def hits(events):
    return {hit.technique_id for hit in detect_aws_events(events, RULES)}


def test_accepted_video_management_events_and_negative_controls():
    assert len(RULES) == 10
    assert hits(EVENTS) == FIELDS
    assert not hits([event for event in EVENTS if event['eventName'].startswith('Get')])
    for event in EVENTS:
        current = hits([event])
        assert len(current) <= 1
        if not current:
            continue
        assert not hits([{**event, 'errorCode': 'AccessDeniedException'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
        assert not hits([{**event, 'readOnly': True}])
        assert not hits([{**event, 'recipientAccountId': '000000000000'}])

    mapping = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'UpdateMediaStorageConfiguration'
                                 and e['requestParameters']['mediaStorageConfiguration']['status'] == 'ENABLED'))
    mapping['requestParameters']['mediaStorageConfiguration']['streamARN'] = mapping['requestParameters'][
        'mediaStorageConfiguration']['streamARN'].replace(':222233334444:', ':000000000000:')
    assert not hits([mapping])

    notify = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'UpdateNotificationConfiguration'
                                and e['requestParameters']['notificationConfiguration']['status'] == 'ENABLED'))
    notify['requestParameters']['notificationConfiguration']['destinationConfig']['uri'] = 'https://example.com/'
    assert not hits([notify])

    image = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'UpdateImageGenerationConfiguration'
                               and e['requestParameters']['imageGenerationConfiguration']['status'] == 'ENABLED'))
    image['requestParameters']['imageGenerationConfiguration']['destinationConfig']['destinationRegion'] = 'eu-west-1'
    assert not hits([image])

    retention = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'UpdateDataRetention'))
    retention['requestParameters']['operation'] = 'INCREASE_DATA_RETENTION'
    assert not hits([retention])
