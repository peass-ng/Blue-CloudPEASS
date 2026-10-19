"""Normalize additional Kinesis stream availability and encryption controls."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NAMES = {'StartStreamEncryption', 'StopStreamEncryption', 'SplitShard',
         'MergeShards', 'UpdateStreamMode'}


def normalize_aws_kinesis_controls_extended(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'kinesis.amazonaws.com' or name not in NAMES
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
    stream = request.get('streamName')
    if not isinstance(stream, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', stream):
        stream = None
    arn = request.get('streamARN')
    if not isinstance(arn, str) or not re.fullmatch(
            rf'arn:aws:kinesis:{re.escape(region)}:{account}:stream/[A-Za-z0-9_.-]{{1,128}}', arn):
        arn = None
    if name == 'UpdateStreamMode' and arn is None:
        return None
    if name != 'UpdateStreamMode' and stream is None:
        return None
    failed = bool(record.get('errorCode') or record.get('errorMessage'))
    shard = request.get('shardToSplit')
    new_key = request.get('newStartingHashKey')
    split = (name == 'SplitShard' and isinstance(shard, str)
             and bool(re.fullmatch(r'shardId-\d{12}', shard))
             and isinstance(new_key, str) and 1 <= len(new_key) <= 39 and new_key.isdecimal()
             and 0 < int(new_key) < 2**128 - 1)
    first, second = request.get('shardToMerge'), request.get('adjacentShardToMerge')
    merged = (name == 'MergeShards' and isinstance(first, str) and isinstance(second, str)
              and bool(re.fullmatch(r'shardId-\d{12}', first))
              and bool(re.fullmatch(r'shardId-\d{12}', second)) and first != second)
    mode = request.get('streamModeDetails')
    on_demand = (name == 'UpdateStreamMode' and isinstance(mode, Mapping)
                 and mode.get('streamMode') == 'ON_DEMAND')
    stopped = (name == 'StopStreamEncryption' and request.get('encryptionType') == 'KMS'
               and isinstance(request.get('keyId'), str) and bool(request['keyId']))
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': name, 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'),
            'target.id': arn if arn is not None else f'arn:aws:kinesis:{region}:{account}:stream/{stream}',
            'request.kinesis_encryption_stopped': not failed and stopped,
            'request.kinesis_shard_split': not failed and split,
            'request.kinesis_shards_merged': not failed and merged,
            'request.kinesis_mode_on_demand': not failed and on_demand}
