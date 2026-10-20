"""Normalize Kinesis Video Streams configuration and destructive management calls."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NAMES = {'UpdateMediaStorageConfiguration', 'UpdateNotificationConfiguration',
         'UpdateImageGenerationConfiguration', 'UpdateDataRetention', 'UpdateStream',
         'DeleteStream', 'DeleteSignalingChannel'}


def _kvs_arn(value: Any, kind: str, region: str, account: str) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(
        rf'arn:aws:kinesisvideo:{re.escape(region)}:{account}:{kind}/[A-Za-z0-9_.-]+/\d+', value))


def normalize_aws_kinesis_video_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'kinesisvideo.amazonaws.com' or name not in NAMES
            or record.get('eventCategory') != 'Management'
            or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True
            or record.get('readOnly') is not False):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region):
        return None
    request = record.get('requestParameters')
    if not isinstance(request, Mapping):
        return None
    stream_arn, channel_arn = request.get('streamARN'), request.get('channelARN')
    valid_stream = _kvs_arn(stream_arn, 'stream', region, account)
    valid_channel = _kvs_arn(channel_arn, 'channel', region, account)
    storage = request.get('mediaStorageConfiguration')
    storage = storage if isinstance(storage, Mapping) else {}
    notification = request.get('notificationConfiguration')
    notification = notification if isinstance(notification, Mapping) else {}
    image = request.get('imageGenerationConfiguration')
    image = image if isinstance(image, Mapping) else {}
    notification_dest = notification.get('destinationConfig')
    notification_dest = notification_dest if isinstance(notification_dest, Mapping) else {}
    topic = notification_dest.get('uri')
    valid_topic = (isinstance(topic, str) and bool(re.fullmatch(
        rf'arn:aws:sns:{re.escape(region)}:\d{{12}}:[A-Za-z0-9_.-]+', topic)))
    image_dest = image.get('destinationConfig')
    image_dest = image_dest if isinstance(image_dest, Mapping) else {}
    uri = image_dest.get('uri')
    valid_image_dest = (isinstance(uri, str) and bool(re.fullmatch(
        r's3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/[^\s]*', uri))
        and image_dest.get('destinationRegion') == region)
    failed = bool(record.get('errorCode') or record.get('errorMessage'))
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    fields = {
        'request.kvs_media_storage_mapped': name == 'UpdateMediaStorageConfiguration'
            and valid_channel and storage.get('status') == 'ENABLED'
            and _kvs_arn(storage.get('streamARN'), 'stream', region, account),
        'request.kvs_media_storage_disabled': name == 'UpdateMediaStorageConfiguration'
            and valid_channel and storage.get('status') == 'DISABLED',
        'request.kvs_notification_destination_enabled': name == 'UpdateNotificationConfiguration'
            and valid_stream and notification.get('status') == 'ENABLED' and valid_topic,
        'request.kvs_notification_disabled': name == 'UpdateNotificationConfiguration'
            and valid_stream and notification.get('status') == 'DISABLED',
        'request.kvs_image_generation_destination_enabled': name == 'UpdateImageGenerationConfiguration'
            and valid_stream and image.get('status') == 'ENABLED' and valid_image_dest,
        'request.kvs_image_generation_disabled': name == 'UpdateImageGenerationConfiguration'
            and valid_stream and image.get('status') == 'DISABLED',
        'request.kvs_retention_decreased': name == 'UpdateDataRetention' and valid_stream
            and request.get('operation') == 'DECREASE_DATA_RETENTION'
            and type(request.get('dataRetentionChangeInHours')) is int
            and request['dataRetentionChangeInHours'] > 0
            and isinstance(request.get('currentVersion'), str) and bool(request['currentVersion']),
        'request.kvs_stream_configuration_updated': name == 'UpdateStream' and valid_stream
            and isinstance(request.get('currentVersion'), str) and bool(request['currentVersion'])
            and (bool(request.get('deviceName')) or bool(request.get('mediaType'))),
        'request.kvs_stream_deleted': name == 'DeleteStream' and valid_stream,
        'request.kvs_signaling_channel_deleted': name == 'DeleteSignalingChannel' and valid_channel,
    }
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': name, 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'),
            'target.id': channel_arn if valid_channel else stream_arn if valid_stream else None,
            **{key: bool(value and not failed) for key, value in fields.items()}}
