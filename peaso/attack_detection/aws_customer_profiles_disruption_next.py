"""Isolated projections for Customer Profiles trigger and destructive mutations."""

from collections.abc import Mapping
import re
from typing import Any


NAMES = {"UpdateEventTrigger", "DeleteProfileObject", "DeleteProfileObjectType",
         "DeleteProfile", "DeleteEventTrigger"}
DOMAIN = re.compile(r"[A-Za-z0-9_-]{1,64}")
OBJECT_TYPE = re.compile(r"[A-Za-z_][A-Za-z_0-9-]{0,254}")
PROFILE_ID = re.compile(r"[a-f0-9]{32}")
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
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    target = f"arn:aws:profile:{region}:{account}:domains/{domain}"
    if name in {"UpdateEventTrigger", "DeleteEventTrigger"}:
        trigger = field(request, "eventTriggerName")
        if not isinstance(trigger, str) or not DOMAIN.fullmatch(trigger):
            return None
        if (name == "UpdateEventTrigger"
                and not any(field(request, key) is not None for key in
                            ("eventTriggerConditions", "eventTriggerLimits", "objectTypeName",
                             "segmentFilter"))):
            return None
        if field(response, "eventTriggerName") is not None and field(response, "eventTriggerName") != trigger:
            return None
        target += "/event-triggers/" + trigger
    elif name == "DeleteProfileObject":
        object_type, profile_id, key = (field(request, "objectTypeName"),
                                        field(request, "profileId"),
                                        field(request, "profileObjectUniqueKey"))
        if (not isinstance(object_type, str) or not OBJECT_TYPE.fullmatch(object_type)
                or not isinstance(profile_id, str) or not PROFILE_ID.fullmatch(profile_id)
                or not isinstance(key, str) or not 1 <= len(key) <= 255):
            return None
        # Profile IDs and object keys are excluded from rule evidence.
        target += "/object-types/" + object_type
    elif name == "DeleteProfileObjectType":
        object_type = field(request, "objectTypeName")
        if not isinstance(object_type, str) or not OBJECT_TYPE.fullmatch(object_type):
            return None
        target += "/object-types/" + object_type
    else:
        profile_id = field(request, "profileId")
        if not isinstance(profile_id, str) or not PROFILE_ID.fullmatch(profile_id):
            return None
        target += "/profiles/" + profile_id
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    names = {"UpdateEventTrigger": "event_trigger_updated",
             "DeleteProfileObject": "profile_object_deleted",
             "DeleteProfileObjectType": "profile_object_type_deleted",
             "DeleteProfile": "profile_deleted",
             "DeleteEventTrigger": "event_trigger_deleted"}
    return {"cloud.provider": "aws", "event.source": "profile.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"),
            "target.id": target, "request.customer_profiles_" + names[name]: True}
