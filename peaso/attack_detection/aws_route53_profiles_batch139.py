"""Route 53 Profile configuration signals from successful management events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any
from urllib.parse import unquote

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_PROFILE = re.compile(r"rp-[A-Za-z0-9-]+\Z")
_VPC = re.compile(r"vpc-[a-f0-9]+\Z")
_ROUTES = {
    "CreateProfile": ("ProfileCreated", "request.route53_profile_created"),
    "AssociateResourceToProfile": ("ProfileResourceAssociated", "request.route53_profile_resource_associated"),
    "UpdateProfileResourceAssociation": ("ProfileResourceAssociationUpdated", "request.route53_profile_resource_updated"),
    "AssociateProfile": ("ProfileAssociatedToVpc", "request.route53_profile_vpc_associated"),
    "DisassociateResourceFromProfile": ("ProfileResourceDisassociated", "request.route53_profile_resource_disassociated"),
    "DisassociateProfile": ("ProfileDisassociatedFromVpc", "request.route53_profile_vpc_disassociated"),
}


def _stamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    request, response = record.get("requestParameters"), record.get("responseElements")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (route is None or record.get("eventSource") != "route53profiles.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or _stamp(record.get("eventTime")) is None):
        return []
    if name == "CreateProfile":
        detail = response.get("Profile")
        profile = detail.get("Id") if isinstance(detail, Mapping) else None
        if (not isinstance(profile, str) or not _PROFILE.fullmatch(profile)
                or detail.get("Arn") != f"arn:aws:route53profiles:{region}:{account}:profile/{profile}"
                or detail.get("OwnerId") != account
                or detail.get("Name") != request.get("Name")):
            return []
        target = profile
    else:
        key = "ProfileAssociation" if name in ("AssociateProfile", "DisassociateProfile") else "ProfileResourceAssociation"
        detail = response.get(key)
        profile = (detail.get("ProfileId") if name == "UpdateProfileResourceAssociation"
                   and isinstance(detail, Mapping) else request.get("ProfileId"))
        if (not isinstance(detail, Mapping)
                or not isinstance(profile, str) or not _PROFILE.fullmatch(profile)
                or detail.get("ProfileId") != profile
                or detail.get("OwnerId") != account):
            return []
        if name in ("AssociateProfile", "DisassociateProfile"):
            vpc = request.get("ResourceId")
            if (not isinstance(vpc, str) or not _VPC.fullmatch(vpc)
                    or detail.get("ResourceId") != vpc):
                return []
            target = vpc
        else:
            arn = (detail.get("ResourceArn") if name == "UpdateProfileResourceAssociation"
                   else unquote(request.get("ResourceArn"))
                   if isinstance(request.get("ResourceArn"), str) else None)
            if (not isinstance(arn, str) or not arn.startswith("arn:aws:")
                    or detail.get("ResourceArn") != arn):
                return []
            target = profile
            if name == "UpdateProfileResourceAssociation":
                assoc = request.get("ProfileResourceAssociationId")
                if (not isinstance(assoc, str) or detail.get("Id") != assoc
                        or ("Name" not in request and "ResourceProperties" not in request)
                        or ("Name" in request and detail.get("Name") != request["Name"])
                        or ("ResourceProperties" in request
                            and detail.get("ResourceProperties") != request["ResourceProperties"])
                        or detail.get("Status") not in ("UPDATING", "COMPLETE")):
                    return []
        if name in ("AssociateResourceToProfile", "AssociateProfile") and detail.get("Status") not in ("CREATING", "COMPLETE"):
            return []
        if name in ("DisassociateResourceFromProfile", "DisassociateProfile") and detail.get("Status") not in ("DELETING", "DELETED"):
            return []
    actor = record.get("userIdentity")
    synthetic, marker = route
    return [{
        "cloud.provider": "aws", "event.source": "route53profiles.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": target, "request.route53_profile_id": profile,
        marker: True,
    }]


def correlate_resource_vpc(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    resources: dict[tuple[str, str], list[tuple[datetime, Mapping[str, Any]]]] = {}
    vpcs: dict[tuple[str, str], list[tuple[datetime, Mapping[str, Any]]]] = {}
    for record in records:
        normalized = normalize(record)
        if not normalized:
            continue
        event = normalized[0]
        key = event["account.id"], event["request.route53_profile_id"]
        stamp = _stamp(event["event.time"])
        if stamp is None:
            continue
        if event["event.name"] == "ProfileResourceAssociated":
            resources.setdefault(key, []).append((stamp, event))
        elif event["event.name"] == "ProfileAssociatedToVpc":
            vpcs.setdefault(key, []).append((stamp, event))
    output = []
    for key in resources.keys() & vpcs.keys():
        for resource_time, resource in resources[key]:
            for vpc_time, vpc in vpcs[key]:
                if abs(vpc_time - resource_time) > timedelta(hours=1):
                    continue
                later = resource if resource_time >= vpc_time else vpc
                output.append({
                    "cloud.provider": "aws", "event.source": "route53profiles.amazonaws.com",
                    "event.name": "ProfileResourceAndVpcAssociated", "event.outcome": "success",
                    "event.id": later["event.id"], "event.time": later["event.time"],
                    "account.id": key[0], "actor.id": later["actor.id"],
                    "target.id": vpc["target.id"],
                    "request.route53_profile_resource_vpc_associated": True,
                })
    return output
