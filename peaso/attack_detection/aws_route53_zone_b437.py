"""Route 53 DNS and private-zone VPC association management facts."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from typing import Any


_NAMES = {"ChangeResourceRecordSets", "CreateVPCAssociationAuthorization",
          "AssociateVPCWithHostedZone"}
_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "TXT"}


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def normalize_aws_route53_zone_b437(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "route53.amazonaws.com" or record.get("eventName") not in _NAMES:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    zone = request.get("hostedZoneId")
    zone = zone if isinstance(zone, str) and bool(zone) else None
    name = record["eventName"]
    batch = request.get("changeBatch")
    batch = batch if isinstance(batch, Mapping) else {}
    changes = batch.get("changes")
    changes = changes if isinstance(changes, list) else []
    actions: set[str] = set()
    for change in changes:
        if not isinstance(change, Mapping):
            continue
        rr = change.get("resourceRecordSet")
        if (isinstance(rr, Mapping) and isinstance(rr.get("name"), str) and rr["name"]
                and rr.get("type") in _TYPES and change.get("action") in {"CREATE", "UPSERT", "DELETE"}):
            actions.add(change["action"])
    vpc = request.get("vPC")
    vpc = vpc if isinstance(vpc, Mapping) else {}
    vpc_id = vpc.get("vPCId")
    vpc_region = vpc.get("vPCRegion")
    valid_vpc = (isinstance(vpc_id, str) and vpc_id.startswith("vpc-")
                 and isinstance(vpc_region, str) and bool(vpc_region))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    target = zone + ":" + vpc_region + ":" + vpc_id if zone and valid_vpc else zone
    return {
        "cloud.provider": "aws", "event.source": "route53.amazonaws.com", "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"),
        "actor.id": _hash(identity["arn"]) if isinstance(identity.get("arn"), str) else None,
        "target.id": _hash(target) if isinstance(target, str) else None,
        "request.route53_dns_create_observed": bool(not failed and zone and name == "ChangeResourceRecordSets"
                                                     and "CREATE" in actions),
        "request.route53_dns_upsert_observed": bool(not failed and zone and name == "ChangeResourceRecordSets"
                                                     and "UPSERT" in actions),
        "request.route53_dns_delete_observed": bool(not failed and zone and name == "ChangeResourceRecordSets"
                                                     and "DELETE" in actions),
        "request.route53_vpc_association_authorized": bool(not failed and zone and valid_vpc
                                                            and name == "CreateVPCAssociationAuthorization"),
        "request.route53_vpc_associated": bool(not failed and zone and valid_vpc
                                                and name == "AssociateVPCWithHostedZone"),
    }
