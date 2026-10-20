"""Normalize Kinesis Data Streams control-plane changes observed in CloudTrail."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


NAMES = {'DecreaseStreamRetentionPeriod', 'DisableEnhancedMonitoring', 'PutResourcePolicy',
         'RegisterStreamConsumer', 'DeleteStream', 'UpdateShardCount', 'UpdateMaxRecordSize'}


def normalize_aws_kinesis_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'kinesis.amazonaws.com' or name not in NAMES
            or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region):
        return None
    request = record.get('requestParameters')
    if not isinstance(request, Mapping):
        return None
    failed = bool(record.get('errorCode') or record.get('errorMessage'))
    stream = request.get('streamARN')
    stream_prefix = f'arn:aws:kinesis:{region}:{account}:stream/'
    valid_stream = (isinstance(stream, str) and stream.startswith(stream_prefix)
                    and bool(stream[len(stream_prefix):]) and '/' not in stream[len(stream_prefix):])
    resource = request.get('resourceARN')
    valid_resource = isinstance(resource, str) and resource.startswith(stream_prefix)
    is_consumer = valid_resource and bool(re.fullmatch(
        re.escape(stream_prefix) + r'[A-Za-z0-9_.-]+/consumer/[A-Za-z0-9_.-]+:\d+', resource))
    is_stream_policy = valid_resource and bool(resource[len(stream_prefix):]) and '/' not in resource[len(stream_prefix):]
    raw_policy = request.get('policy')
    try: policy = json.loads(raw_policy) if isinstance(raw_policy, str) else None
    except (json.JSONDecodeError, TypeError): policy = None
    statements = policy.get('Statement') if isinstance(policy, Mapping) else None
    statements = statements if isinstance(statements, list) else []
    subscribe_grant = any(
        isinstance(s, Mapping) and s.get('Effect') == 'Allow' and s.get('Resource') == resource
        and isinstance(s.get('Principal'), Mapping) and bool(s['Principal'].get('AWS'))
        and 'kinesis:SubscribeToShard' in (s.get('Action') if isinstance(s.get('Action'), list) else [s.get('Action')])
        for s in statements)
    response = record.get('responseElements')
    response = response if isinstance(response, Mapping) else {}
    consumer = response.get('consumer')
    consumer = consumer if isinstance(consumer, Mapping) else {}
    valid_consumer = (valid_stream and isinstance(request.get('consumerName'), str)
                      and bool(request['consumerName']) and consumer.get('consumerName') == request['consumerName']
                      and isinstance(consumer.get('consumerARN'), str)
                      and bool(re.fullmatch(re.escape(stream + '/consumer/' + request['consumerName']) + r':\d+',
                                            consumer['consumerARN'])))
    metrics = request.get('shardLevelMetrics')
    current = response.get('currentShardLevelMetrics')
    desired = response.get('desiredShardLevelMetrics')
    monitor_arn = response.get('streamARN')
    monitor_target = (isinstance(monitor_arn, str) and monitor_arn.startswith(stream_prefix)
                      and bool(monitor_arn[len(stream_prefix):]) and '/' not in monitor_arn[len(stream_prefix):]
                      and (not request.get('streamName') or monitor_arn.endswith('/' + request['streamName'])))
    disabled_metrics = (monitor_target and isinstance(metrics, list) and bool(metrics)
                        and isinstance(current, list) and isinstance(desired, list)
                        and bool(set(current) - set(desired)))
    scaled = (valid_stream and type(request.get('targetShardCount')) is int
              and type(response.get('currentShardCount')) is int
              and response.get('targetShardCount') == request['targetShardCount']
              and request['targetShardCount'] != response['currentShardCount']
              and response.get('streamARN') == stream)
    raised_record_limit = (valid_stream and type(request.get('maxRecordSizeInKiB')) is int
                           and request['maxRecordSizeInKiB'] > 1024)
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': name, 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'),
            'target.id': resource if valid_resource else stream if valid_stream else request.get('streamName'),
            'request.kinesis_retention_decreased': name == 'DecreaseStreamRetentionPeriod' and valid_stream
                and type(request.get('retentionPeriodHours')) is int and not failed,
            'request.kinesis_monitoring_disabled': name == 'DisableEnhancedMonitoring' and disabled_metrics and not failed,
            'request.kinesis_stream_policy_changed': name == 'PutResourcePolicy' and is_stream_policy and bool(statements) and not failed,
            'request.kinesis_consumer_subscription_granted': name == 'PutResourcePolicy' and is_consumer and subscribe_grant and not failed,
            'request.kinesis_consumer_registered': name == 'RegisterStreamConsumer' and valid_consumer and not failed,
            'request.kinesis_stream_deleted': name == 'DeleteStream' and valid_stream and not failed,
            'request.kinesis_shard_count_changed': name == 'UpdateShardCount' and scaled and not failed,
            'request.kinesis_record_limit_raised': name == 'UpdateMaxRecordSize' and raised_record_limit and not failed}
