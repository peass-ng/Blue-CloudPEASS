"""Isolated precursor for Kinesis write data events; no payload retention."""

from collections.abc import Mapping
import re
from typing import Any


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "kinesis.amazonaws.com"
            or name not in {"PutRecord", "PutRecords"}
            or record.get("eventCategory") != "Data"
            or record.get("eventType") != "AwsApiCall"
            # CloudTrail currently marks observed PutRecord/PutRecords data
            # events readOnly=true. The event name and outcome identify writes.
            or not isinstance(record.get("readOnly"), bool)
            or record.get("managementEvent") is True):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    arn = request.get("streamARN") or request.get("streamArn")
    stream_name = request.get("streamName")
    prefix = f"arn:aws:kinesis:{region}:{account}:stream/"
    if isinstance(arn, str):
        if not arn.startswith(prefix) or not re.fullmatch(r"[A-Za-z0-9_.-]+", arn[len(prefix):]):
            return None
        target = arn
        if stream_name is not None and stream_name != arn[len(prefix):]:
            return None
    elif isinstance(stream_name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", stream_name):
        target = prefix + stream_name
    else:
        return None
    resources = record.get("resources")
    if isinstance(resources, list) and resources:
        stream_resources = [r.get("ARN") for r in resources if isinstance(r, Mapping)
                            and r.get("type") == "AWS::Kinesis::Stream"]
        if stream_resources and target not in stream_resources:
            return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    if request.get("dryRun") is True or failed:
        return None
    if name == "PutRecord":
        response = record.get("responseElements")
        confirmed = isinstance(response, Mapping) and bool(response.get("sequenceNumber"))
    else:
        response = record.get("responseElements")
        confirmed = (isinstance(response, Mapping)
                     and isinstance(response.get("records"), list)
                     and any(isinstance(item, Mapping) and bool(item.get("sequenceNumber"))
                             for item in response["records"]))
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "kinesis.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
        "request.kinesis_write_request_accepted": True,
        "request.kinesis_record_insert_confirmed": confirmed,
    }
