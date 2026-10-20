"""Isolated precursor for Kinesis read data events; never retain iterators or records."""

from collections.abc import Mapping
import re
from typing import Any


STREAM_NAME = re.compile(r"[A-Za-z0-9_.-]+")
SHARD_NAME = re.compile(r"shardId-[0-9]{12}")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "kinesis.amazonaws.com"
            or name not in {"GetShardIterator", "GetRecords", "SubscribeToShard"}
            or record.get("eventCategory") != "Data"
            or record.get("eventType") != "AwsApiCall"
            or record.get("readOnly") is not True
            or record.get("managementEvent") is True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping) or request.get("dryRun") is True:
        return None
    stream_prefix = f"arn:aws:kinesis:{region}:{account}:stream/"
    target = None
    if name == "GetShardIterator":
        if not isinstance(request.get("shardId"), str) or not SHARD_NAME.fullmatch(request["shardId"]):
            return None
        if request.get("shardIteratorType") not in {
                "TRIM_HORIZON", "LATEST", "AT_SEQUENCE_NUMBER", "AFTER_SEQUENCE_NUMBER", "AT_TIMESTAMP"}:
            return None
        stream = request.get("streamARN") or request.get("streamArn")
        stream_name = request.get("streamName")
        if isinstance(stream, str) and stream.startswith(stream_prefix) and STREAM_NAME.fullmatch(stream[len(stream_prefix):]):
            if stream_name is not None and stream_name != stream[len(stream_prefix):]:
                return None
            target = stream
        elif isinstance(stream_name, str) and STREAM_NAME.fullmatch(stream_name) and stream is None:
            target = stream_prefix + stream_name
    elif name == "GetRecords":
        # The request only contains an opaque shard iterator. Attribute the stream
        # from CloudTrail's resource list; never emit or persist the iterator.
        if not isinstance(request.get("shardIterator"), str) or not request["shardIterator"]:
            return None
    else:
        consumer = request.get("consumerARN") or request.get("consumerArn")
        if (isinstance(consumer, str) and re.fullmatch(
                re.escape(stream_prefix) + r"[A-Za-z0-9_.-]+/consumer/[A-Za-z0-9_.-]+:[0-9]+", consumer)
                and isinstance(request.get("shardId"), str)
                and SHARD_NAME.fullmatch(request["shardId"])):
            target = consumer
    resources = record.get("resources")
    resource_type = "AWS::Kinesis::StreamConsumer" if name == "SubscribeToShard" else "AWS::Kinesis::Stream"
    matched_resources = [r.get("ARN") for r in resources if isinstance(r, Mapping)
                         and r.get("type") == resource_type] if isinstance(resources, list) else []
    if name == "GetRecords":
        valid = [r for r in matched_resources if isinstance(r, str) and r.startswith(stream_prefix)
                 and STREAM_NAME.fullmatch(r[len(stream_prefix):])]
        if len(valid) != 1:
            return None
        target = valid[0]
    elif target is not None and matched_resources and target not in matched_resources:
        return None
    if target is None:
        return None
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "kinesis.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
        "request.kinesis_get_shard_iterator": name == "GetShardIterator",
        "request.kinesis_get_records": name == "GetRecords",
        "request.kinesis_subscribe_to_shard": name == "SubscribeToShard",
    }
