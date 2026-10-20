"""Isolated Customer Profiles control-plane signals; excludes key values and PII."""

from collections.abc import Mapping
import re
from typing import Any


NAMES = {"AddProfileKey", "CreateEventStream", "MergeProfiles", "UpdateDomain", "DeleteDomain"}
DOMAIN = re.compile(r"[A-Za-z0-9_-]{1,64}")
PROFILE_ID = re.compile(r"[a-f0-9]{32}")


def field(value: Mapping[str, Any], name: str) -> Any:
    """CloudTrail uses initial caps for this service; accept SDK-style too."""
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
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    domain = field(request, "domainName")
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain):
        return None
    base = f"arn:aws:profile:{region}:{account}:domains/{domain}"
    target = base
    flags = {"key_added": False, "event_stream_created": False,
             "profiles_merged": False, "auto_merging_enabled": False,
             "domain_deleted": False}
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    if name == "AddProfileKey":
        pid, key = field(request, "profileId"), field(request, "keyName")
        if (not isinstance(pid, str) or not PROFILE_ID.fullmatch(pid)
                or not isinstance(key, str) or not key
                or (field(response, "keyName") is not None and field(response, "keyName") != key)):
            return None
        target = base + "/profiles/" + pid
        flags["key_added"] = True
    elif name == "CreateEventStream":
        stream_name, uri = field(request, "eventStreamName"), field(request, "uri")
        if (not isinstance(stream_name, str) or not DOMAIN.fullmatch(stream_name)
                or not isinstance(uri, str)
                or not re.fullmatch(rf"arn:aws:kinesis:{re.escape(region)}:{account}:stream/[A-Za-z0-9_.-]+", uri)
                or (field(response, "eventStreamArn") is not None
                    and field(response, "eventStreamArn") != base + "/event-streams/" + stream_name)):
            return None
        target = base + "/event-streams/" + stream_name
        flags["event_stream_created"] = True
    elif name == "MergeProfiles":
        main, merged = field(request, "mainProfileId"), field(request, "profileIdsToBeMerged")
        if (not isinstance(main, str) or not PROFILE_ID.fullmatch(main)
                or not isinstance(merged, list) or not 1 <= len(merged) <= 20
                or any(not isinstance(p, str) or not PROFILE_ID.fullmatch(p) or p == main for p in merged)
                or len(set(merged)) != len(merged)):
            return None
        target = base + "/profiles/" + main
        flags["profiles_merged"] = True
    elif name == "UpdateDomain":
        matching = field(request, "matching")
        matching = matching if isinstance(matching, Mapping) else {}
        auto = field(matching, "autoMerging")
        auto = auto if isinstance(auto, Mapping) else {}
        output_matching = field(response, "matching")
        output_matching = output_matching if isinstance(output_matching, Mapping) else {}
        output_auto = field(output_matching, "autoMerging")
        output_auto = output_auto if isinstance(output_auto, Mapping) else {}
        enabled = field(output_auto, "enabled")
        if field(auto, "enabled") is not True or (enabled is not None and enabled is not True):
            return None
        flags["auto_merging_enabled"] = True
    else:
        flags["domain_deleted"] = True
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    out = {"cloud.provider": "aws", "event.source": "profile.amazonaws.com",
           "event.name": name, "event.outcome": "success",
           "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
           "account.id": account, "actor.id": actor.get("arn"), "target.id": target}
    out.update({"request.customer_profiles_" + key: value for key, value in flags.items()})
    return out
