"""Firehose record and destination signals plus SNS delivery role changes."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_STREAM = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_BUCKET = re.compile(r"arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_WINDOW = timedelta(hours=1)


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if result.tzinfo else None


def _base(record: Mapping[str, Any], source: str,
          category: str, read_only: bool | None) -> tuple[str, str, Mapping[str, Any]] | None:
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    response = record.get("responseElements")
    if (record.get("eventSource") != source or record.get("eventCategory") != category
            or record.get("eventType") != "AwsApiCall"
            or (record.get("readOnly") is not read_only if read_only is not None
                else not isinstance(record.get("readOnly"), bool))
            or (category == "Management" and record.get("managementEvent") is not True)
            or (category == "Data" and record.get("managementEvent") is not False)
            or record.get("errorCode") or record.get("errorMessage")
            or (isinstance(response, Mapping)
                and (response.get("errorCode") or response.get("errorMessage")))
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)):
        return None
    return account, region, request


def _stream_arn(region: str, account: str, stream: str) -> str:
    return f"arn:aws:firehose:{region}:{account}:deliverystream/{stream}"


def _finding(record: Mapping[str, Any], account: str, target: str,
             event_name: str, flag: str, prior: str | None = None) -> dict[str, Any]:
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    result = {
        "cloud.provider": "aws", "event.source": record["eventSource"],
        "event.name": event_name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True,
    }
    if prior:
        result["correlation_evidence"] = {"prior_event_id": prior}
    return result


def _firehose(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    if name in {"PutRecord", "PutRecordBatch"}:
        # Firehose records its PutRecordBatch data event with readOnly=true.
        # The API name and Data category identify ingestion; require a boolean
        # but do not infer write success from CloudTrail's readOnly flag.
        base = _base(record, "firehose.amazonaws.com", "Data", None)
    elif name == "DescribeDeliveryStream":
        base = _base(record, "firehose.amazonaws.com", "Management", True)
    elif name in {"UpdateDestination", "DeleteDeliveryStream"}:
        base = _base(record, "firehose.amazonaws.com", "Management", False)
    else:
        return []
    if base is None:
        return []
    account, region, request = base
    stream = request.get("deliveryStreamName")
    if not isinstance(stream, str) or not _STREAM.fullmatch(stream):
        return []
    if name in {"PutRecord", "PutRecordBatch"}:
        resources = record.get("resources")
        if (not isinstance(resources, list) or not any(
            isinstance(x, Mapping) and x.get("type") == "AWS::KinesisFirehose::DeliveryStream"
            and x.get("ARN") == _stream_arn(region, account, stream)
            for x in resources)):
            return []
        response = record.get("responseElements")
        if name == "PutRecordBatch" and isinstance(response, Mapping):
            if response.get("failedPutCount") not in {None, 0}:
                return []
        synthetic = "Firehose" + name + "Accepted"
        flag = "request.firehose_" + ("put_record" if name == "PutRecord" else "put_record_batch")
    elif name == "DescribeDeliveryStream":
        synthetic, flag = "FirehoseTopologyRead", "request.firehose_topology_read"
    elif name == "UpdateDestination":
        update = request.get("extendedS3DestinationUpdate")
        if (not isinstance(update, Mapping) or not isinstance(update.get("bucketARN"), str)
                or not _BUCKET.fullmatch(update["bucketARN"])
                or not isinstance(request.get("currentDeliveryStreamVersionId"), str)
                or not isinstance(request.get("destinationId"), str)):
            return []
        synthetic, flag = "FirehoseS3DestinationUpdate", "request.firehose_s3_destination_update"
    else:
        synthetic, flag = "FirehoseDeliveryStreamDeleted", "request.firehose_stream_deleted"
    return [_finding(record, account, stream, synthetic, flag)]


def _sns(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    if name not in {"Subscribe", "SetSubscriptionAttributes"}:
        return []
    base = _base(record, "sns.amazonaws.com", "Management", False)
    if base is None:
        return []
    account, region, request = base
    if name == "Subscribe":
        endpoint, topic, attrs = (request.get("endpoint"), request.get("topicArn"),
                                  request.get("attributes"))
        response = record.get("responseElements")
        expected_prefix = f"arn:aws:sns:{region}:{account}:"
        if (request.get("protocol") != "firehose" or not isinstance(endpoint, str)
                or not endpoint.startswith(f"arn:aws:firehose:{region}:{account}:deliverystream/")
                or not _STREAM.fullmatch(endpoint.rsplit("/", 1)[-1])
                or not isinstance(topic, str) or not topic.startswith(expected_prefix)
                or not isinstance(attrs, Mapping)
                or not isinstance(attrs.get("SubscriptionRoleArn"), str)
                or not attrs["SubscriptionRoleArn"].startswith(f"arn:aws:iam::{account}:role/")
                or not isinstance(response, Mapping)
                or not isinstance(response.get("subscriptionArn"), str)
                or not response["subscriptionArn"].startswith(expected_prefix)):
            return []
        return [_finding(record, account, endpoint.rsplit("/", 1)[-1],
                         "SNSFirehoseSubscriptionConfirmed",
                         "request.sns_firehose_subscription_confirmed")]
    subscription = request.get("subscriptionArn")
    value = request.get("attributeValue")
    if (request.get("attributeName") != "SubscriptionRoleArn"
            or not isinstance(subscription, str)
            or not subscription.startswith(f"arn:aws:sns:{region}:{account}:")
            or not isinstance(value, str)
            or not value.startswith(f"arn:aws:iam::{account}:role/")):
        return []
    return [_finding(record, account, subscription,
                     "SNSFirehoseDeliveryRoleConfigured",
                     "request.sns_firehose_role_configured")]


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    return _firehose(record) + _sns(record)


def correlate_destination_change(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Compare the latest accepted S3 bucket from Create/Update for one stream."""
    rows = []
    deletes: dict[datetime, list[tuple[str, str, str]]] = defaultdict(list)
    seen_event_ids: set[str] = set()
    for record in records:
        event_id = record.get("eventID")
        if isinstance(event_id, str) and event_id in seen_event_ids:
            continue
        if record.get("eventName") not in {
                "CreateDeliveryStream", "UpdateDestination", "DeleteDeliveryStream"}:
            continue
        base = _base(record, "firehose.amazonaws.com", "Management", False)
        when = _when(record.get("eventTime"))
        if base is None or when is None:
            continue
        account, region, request = base
        stream = request.get("deliveryStreamName")
        if not isinstance(stream, str) or not _STREAM.fullmatch(stream):
            continue
        if record["eventName"] == "DeleteDeliveryStream":
            seen_event_ids.add(record["eventID"])
            deletes[when].append((account, region, stream))
            continue
        config = request.get("extendedS3DestinationConfiguration") if record["eventName"] == "CreateDeliveryStream" else request.get("extendedS3DestinationUpdate")
        bucket = config.get("bucketARN") if isinstance(config, Mapping) else None
        if not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket):
            continue
        seen_event_ids.add(record["eventID"])
        rows.append((when, record, (account, region, stream), bucket))
    grouped: dict[datetime, list[tuple]] = defaultdict(list)
    for row in rows:
        grouped[row[0]].append(row)
    previous: dict[tuple[str, str, str], tuple[datetime, str, str]] = {}
    results = []
    for when in sorted(set(grouped) | set(deletes)):
        for key in deletes[when]:
            previous.pop(key, None)
        group = grouped[when]
        counts: dict[tuple[str, str, str], int] = defaultdict(int)
        for _, _, key, _ in group:
            counts[key] += 1
        for _, record, key, bucket in group:
            prior = previous.get(key)
            if (counts[key] == 1 and record["eventName"] == "UpdateDestination"
                    and prior and when - prior[0] <= _WINDOW and prior[1] != bucket):
                results.append(_finding(record, key[0], key[2],
                    "FirehoseS3DestinationChanged", "request.firehose_s3_destination_changed",
                    prior[2]))
        for _, record, key, bucket in group:
            if counts[key] == 1:
                previous[key] = when, bucket, record["eventID"]
            else:
                previous.pop(key, None)
    return results


def correlate_sns_role_rebound(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    seen_event_ids: set[str] = set()
    for record in records:
        if record.get("eventName") not in {"Subscribe", "SetSubscriptionAttributes"}:
            continue
        event_id = record.get("eventID")
        if isinstance(event_id, str) and event_id in seen_event_ids:
            continue
        if not _sns(record):
            continue
        base = _base(record, "sns.amazonaws.com", "Management", False)
        when = _when(record.get("eventTime"))
        if base is None or when is None:
            continue
        account, region, request = base
        if record["eventName"] == "Subscribe":
            response = record.get("responseElements")
            attrs = request.get("attributes")
            subscription = response.get("subscriptionArn") if isinstance(response, Mapping) else None
            role = attrs.get("SubscriptionRoleArn") if isinstance(attrs, Mapping) else None
            if request.get("protocol") != "firehose":
                continue
        else:
            subscription = request.get("subscriptionArn")
            role = request.get("attributeValue")
            if request.get("attributeName") != "SubscriptionRoleArn":
                continue
        if (not isinstance(subscription, str)
                or not subscription.startswith(f"arn:aws:sns:{region}:{account}:")
                or not isinstance(role, str)
                or not role.startswith(f"arn:aws:iam::{account}:role/")):
            continue
        seen_event_ids.add(record["eventID"])
        rows.append((when, record, (account, region, subscription), role))
    grouped: dict[datetime, list[tuple]] = defaultdict(list)
    for row in rows:
        grouped[row[0]].append(row)
    previous: dict[tuple[str, str, str], tuple[datetime, str, str]] = {}
    results = []
    for when in sorted(grouped):
        group = grouped[when]
        counts: dict[tuple[str, str, str], int] = defaultdict(int)
        for _, _, key, _ in group:
            counts[key] += 1
        for _, record, key, role in group:
            prior = previous.get(key)
            if (counts[key] == 1 and record["eventName"] == "SetSubscriptionAttributes"
                    and prior and when - prior[0] <= _WINDOW and prior[1] != role):
                results.append(_finding(record, key[0], key[2],
                    "SNSFirehoseDeliveryRoleRebound", "request.sns_firehose_role_rebound",
                    prior[2]))
        for _, record, key, role in group:
            if counts[key] == 1:
                previous[key] = when, role, record["eventID"]
            else:
                previous.pop(key, None)
    return results
