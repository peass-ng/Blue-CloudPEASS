"""Isolated Customer Profiles mutation and upload-job CloudTrail projections.

Only action metadata is retained; no profile fields, CSV mappings, object bodies or
batch item identifiers are copied to detection evidence. Raw shape needs live proof.
"""

from collections.abc import Mapping
import re
from typing import Any


NAMES = {"CreateProfile", "UpdateProfile", "BatchPutProfileObject",
         "PutProfileObjectType", "CreateUploadJob"}
DOMAIN = re.compile(r"[A-Za-z0-9_-]{1,64}")
OBJECT_TYPE = re.compile(r"[A-Za-z_][A-Za-z_0-9-]{0,254}")
PROFILE_ID = re.compile(r"[a-f0-9]{32}")
REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]")


def field(value: Mapping[str, Any], name: str) -> Any:
    """CloudTrail uses initial capitals for Customer Profiles parameters."""
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
    profile_fields = {"accountNumber", "additionalInformation", "address", "attributes",
                      "billingAddress", "birthDate", "businessEmailAddress", "emailAddress",
                      "firstName", "gender", "homePhoneNumber", "lastName", "mailingAddress",
                      "middleName", "mobilePhoneNumber", "partyType", "personalEmailAddress",
                      "phoneNumber", "shippingAddress"}
    if name == "CreateProfile":
        if not any(field(request, key) is not None for key in profile_fields):
            return None
        response_id = field(response, "profileId")
        if response_id is not None and (not isinstance(response_id, str)
                                        or not PROFILE_ID.fullmatch(response_id)):
            return None
    elif name == "UpdateProfile":
        profile_id = field(request, "profileId")
        if (not isinstance(profile_id, str) or not PROFILE_ID.fullmatch(profile_id)
                or not any(field(request, key) is not None for key in profile_fields)):
            return None
        target += "/profiles/" + profile_id
        if field(response, "profileId") is not None and field(response, "profileId") != profile_id:
            return None
    elif name == "BatchPutProfileObject":
        object_type, items = field(request, "objectTypeName"), field(request, "items")
        if (not isinstance(object_type, str) or not OBJECT_TYPE.fullmatch(object_type)
                or not isinstance(items, list) or not 1 <= len(items) <= 10
                or not all(isinstance(item, Mapping) for item in items)):
            return None
        target += "/object-types/" + object_type
        if field(response, "successful") is not None:
            success = field(response, "successful")
            if not isinstance(success, list) or not success:
                return None
    elif name == "PutProfileObjectType":
        object_type = field(request, "objectTypeName")
        if (not isinstance(object_type, str) or not OBJECT_TYPE.fullmatch(object_type)
                or not any(field(request, key) is not None for key in
                           ("fields", "keys", "allowProfileCreation", "sourcePriority",
                            "expirationDays", "maxProfileObjectCount"))):
            return None
        target += "/object-types/" + object_type
        if field(response, "objectTypeName") is not None and field(response, "objectTypeName") != object_type:
            return None
    else:
        display_name, fields, unique_key = (field(request, "displayName"),
                                            field(request, "fields"), field(request, "uniqueKey"))
        if (not isinstance(display_name, str) or not 1 <= len(display_name) <= 255
                or not fields or not isinstance(fields, (Mapping, str))
                or not isinstance(unique_key, str) or not 1 <= len(unique_key) <= 1000):
            return None
        job_id = field(response, "jobId")
        if job_id is not None and (not isinstance(job_id, str)
                                   or not PROFILE_ID.fullmatch(job_id)):
            return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    names = {"CreateProfile": "profile_created", "UpdateProfile": "profile_updated",
             "BatchPutProfileObject": "profile_object_batch_ingested",
             "PutProfileObjectType": "profile_object_type_changed",
             "CreateUploadJob": "upload_job_created"}
    return {"cloud.provider": "aws", "event.source": "profile.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"),
            "target.id": target, "request.customer_profiles_" + names[name]: True}
