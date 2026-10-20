"""Five isolated Customer Profiles path observations; suppress bodies and upload keys."""
from collections.abc import Mapping
import re
from typing import Any

NAMES = {"CreateEventTrigger", "GetUploadJobPath", "PutProfileObject",
         "DeleteEventStream", "DeleteCalculatedAttributeDefinition"}
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
            or record.get("readOnly") is not (name == "GetUploadJobPath")
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
    if name == "CreateEventTrigger":
        trigger, object_type, conditions = (field(request, "eventTriggerName"),
                                            field(request, "objectTypeName"),
                                            field(request, "eventTriggerConditions"))
        if (not isinstance(trigger, str) or not DOMAIN.fullmatch(trigger)
                or not isinstance(object_type, str) or not OBJECT_TYPE.fullmatch(object_type)
                or not conditions or not isinstance(conditions, (str, list))
                or (field(response, "eventTriggerName") is not None
                    and field(response, "eventTriggerName") != trigger)):
            return None
        target += "/event-triggers/" + trigger
    elif name == "GetUploadJobPath":
        job = field(request, "jobId")
        if not isinstance(job, str) or not PROFILE_ID.fullmatch(job):
            return None
        target += "/upload-jobs/" + job
    elif name == "PutProfileObject":
        object_type, body = field(request, "objectTypeName"), field(request, "object")
        if (not isinstance(object_type, str) or not OBJECT_TYPE.fullmatch(object_type)
                or body is None or not isinstance(body, (str, Mapping))
                or (field(response, "profileObjectUniqueKey") is not None
                    and not isinstance(field(response, "profileObjectUniqueKey"), str))):
            return None
        target += "/object-types/" + object_type
    elif name == "DeleteEventStream":
        stream = field(request, "eventStreamName")
        if not isinstance(stream, str) or not DOMAIN.fullmatch(stream):
            return None
        target += "/event-streams/" + stream
    else:
        calculated = field(request, "calculatedAttributeName")
        if not isinstance(calculated, str) or not OBJECT_TYPE.fullmatch(calculated):
            return None
        target += "/calculated-attributes/" + calculated
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    flags = {"CreateEventTrigger": "event_trigger_created",
             "GetUploadJobPath": "upload_job_path_accessed",
             "PutProfileObject": "profile_object_ingested",
             "DeleteEventStream": "event_stream_deleted",
             "DeleteCalculatedAttributeDefinition": "calculated_attribute_deleted"}
    return {"cloud.provider": "aws", "event.source": "profile.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
            "request.customer_profiles_" + flags[name]: True}
