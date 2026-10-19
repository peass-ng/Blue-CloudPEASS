"""Normalize a Kinesis channel S3 delivery created for an account stream."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_kinesis_channel(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get('eventSource') != 'kinesis.amazonaws.com'
            or record.get('eventName') != 'CreateChannel'
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
    request, response = record.get('requestParameters'), record.get('responseElements')
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    description = response.get('channelDescription')
    if not isinstance(description, Mapping):
        return None
    name, channel_id = request.get('channelName'), description.get('channelId')
    channel_arn = description.get('channelARN')
    valid_channel = (isinstance(name, str) and bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', name))
                     and isinstance(channel_id, str) and bool(re.fullmatch(r'[A-Za-z0-9]+', channel_id))
                     and channel_arn == f'arn:aws:kinesis:{region}:{account}:channel/{channel_id}'
                     and description.get('channelName') == name)
    role = request.get('serviceExecutionRoleARN')
    valid_role = (isinstance(role, str) and role.startswith(f'arn:aws:iam::{account}:role/')
                  and description.get('serviceExecutionRoleARN') == role)
    streams = request.get('streamConfigurationList')
    returned_streams = description.get('streamConfigurationList')
    source = streams[0] if isinstance(streams, list) and len(streams) == 1 else None
    returned = returned_streams[0] if isinstance(returned_streams, list) and len(returned_streams) == 1 else None
    stream_arn = source.get('streamARN') if isinstance(source, Mapping) else None
    valid_stream = (isinstance(stream_arn, str)
                    and bool(re.fullmatch(rf'arn:aws:kinesis:{re.escape(region)}:{account}:stream/[A-Za-z0-9_.-]{{1,128}}', stream_arn))
                    and isinstance(returned, Mapping) and returned.get('streamARN') == stream_arn)
    dest = request.get('s3DestinationConfiguration')
    returned_dest = description.get('s3DestinationConfiguration')
    storage = dest.get('storageConfiguration') if isinstance(dest, Mapping) else None
    returned_storage = returned_dest.get('storageConfiguration') if isinstance(returned_dest, Mapping) else None
    bucket = storage.get('bucketARN') if isinstance(storage, Mapping) else None
    owner = storage.get('expectedBucketOwner') if isinstance(storage, Mapping) else None
    valid_dest = (isinstance(bucket, str) and bool(re.fullmatch(r'arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket))
                  and isinstance(owner, str) and bool(re.fullmatch(r'\d{12}', owner))
                  and isinstance(returned_storage, Mapping)
                  and returned_storage.get('bucketARN') == bucket
                  and returned_storage.get('expectedBucketOwner') == owner)
    failed = bool(record.get('errorCode') or record.get('errorMessage'))
    accepted = (not failed and valid_channel and valid_role and valid_stream and valid_dest
                and description.get('channelStatus') in {'CREATING', 'ACTIVE'})
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': 'CreateChannel', 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'),
            'target.id': channel_arn if valid_channel else None,
            'request.kinesis_s3_channel_created': accepted,
            'request.kinesis_s3_channel_cross_account': accepted and owner != account}
