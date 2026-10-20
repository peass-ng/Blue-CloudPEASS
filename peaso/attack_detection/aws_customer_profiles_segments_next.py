"""Isolated Customer Profiles segment stream and subscription observations."""
from collections.abc import Mapping
import re
from typing import Any

NAMES = {"AssociateStreamForSegments", "PutSegmentSubscription",
         "DeleteSegmentSubscription", "DisassociateStreamForSegments",
         "DeleteSegmentDefinition"}
DOMAIN = re.compile(r"[A-Za-z0-9_-]{1,64}")
REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]")


def field(value: Mapping[str, Any], name: str) -> Any:
    return value.get(name, value.get(name[0].upper() + name[1:]))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "profile.amazonaws.com" or name not in NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, request = (record.get("recipientAccountId"), record.get("awsRegion"),
                                record.get("requestParameters"))
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not REGION.fullmatch(region)
            or not isinstance(request, Mapping)):
        return None
    domain = field(request, "domainName")
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain):
        return None
    target = f"arn:aws:profile:{region}:{account}:domains/{domain}"
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    if name == "AssociateStreamForSegments":
        dest, role = field(request, "destinationArn"), field(request, "destinationRoleArn")
        if (not isinstance(dest, str)
                or not re.fullmatch(rf"arn:aws:kinesis:{re.escape(region)}:{account}:stream/[A-Za-z0-9_.-]+", dest)
                or not isinstance(role, str)
                or not re.fullmatch(rf"arn:aws:iam::{account}:role/[A-Za-z0-9_+=,.@/-]+", role)):
            return None
        target += "/segment-streams"
    elif name in {"PutSegmentSubscription", "DeleteSegmentSubscription", "DeleteSegmentDefinition"}:
        segment = field(request, "segmentDefinitionName")
        if not isinstance(segment, str) or not DOMAIN.fullmatch(segment):
            return None
        target += "/segment-definitions/" + segment
        if name == "PutSegmentSubscription":
            schedule = field(request, "scheduleConfiguration")
            if schedule is not None:
                if (not isinstance(schedule, Mapping)
                        or type(field(schedule, "interval")) is not int
                        or not 1 <= field(schedule, "interval") <= 24
                        or field(schedule, "unit") != "HOURLY"):
                    return None
            status = field(response, "status")
            if status is not None and status not in {"STARTING", "RUNNING"}:
                return None
    else:
        target += "/segment-streams"
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    flags = {"AssociateStreamForSegments": "segment_stream_associated",
             "PutSegmentSubscription": "segment_subscription_put",
             "DeleteSegmentSubscription": "segment_subscription_deleted",
             "DisassociateStreamForSegments": "segment_stream_disassociated",
             "DeleteSegmentDefinition": "segment_definition_deleted"}
    return {"cloud.provider": "aws", "event.source": "profile.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
            "request.customer_profiles_" + flags[name]: True}
