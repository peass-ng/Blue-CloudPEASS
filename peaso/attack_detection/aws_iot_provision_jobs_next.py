"""IoT provisioning and job-document signals from CloudTrail management events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-\d\Z")
_NAME = re.compile(r"[A-Za-z0-9_=@-]{1,128}\Z")
_CERT_ID = re.compile(r"[0-9a-f]{64}\Z")


def _common(record: Mapping[str, Any], *, read: bool = False):
    if (record.get("eventSource") != "iot.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not read
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping)
            or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    return account, region, identity["arn"], when, request


def _event(record: Mapping[str, Any], actor: str, account: str, target: str,
           flag: str):
    return {
        "cloud.provider": "aws", "event.source": "iot.amazonaws.com",
        "event.name": record["eventName"], "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": actor, "target.id": target,
        flag: True,
    }


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if not isinstance(name, str) or name not in {
        "CreateProvisioningTemplate", "CreateProvisioningClaim",
        "RegisterCertificateWithoutCA", "GetJobDocument",
    }:
        return None
    common = _common(record, read=name == "GetJobDocument")
    if common is None:
        return None
    account, region, actor, _when, request = common
    response = record.get("responseElements")
    if name == "CreateProvisioningTemplate":
        template, role = request.get("templateName"), request.get("provisioningRoleArn")
        if (not isinstance(template, str) or not _NAME.fullmatch(template)
                or request.get("enabled") is not True
                or not isinstance(role, str)
                or not role.startswith(f"arn:aws:iam::{account}:role/")
                or not isinstance(response, Mapping)
                or response.get("templateName") != template
                or response.get("templateArn")
                   != f"arn:aws:iot:{region}:{account}:provisioningtemplate/{template}"):
            return None
        return _event(record, actor, account, response["templateArn"],
                      "request.iot_enabled_provisioning_template_created")
    if name == "CreateProvisioningClaim":
        template = request.get("templateName")
        if (not isinstance(template, str) or not _NAME.fullmatch(template)
                or not isinstance(response, Mapping)
                or not isinstance(response.get("certificateId"), str)
                or not _CERT_ID.fullmatch(response["certificateId"])):
            return None
        return _event(record, actor, account,
                      f"arn:aws:iot:{region}:{account}:provisioningtemplate/{template}",
                      "request.iot_provisioning_claim_issued")
    if name == "RegisterCertificateWithoutCA":
        if (request.get("status") != "ACTIVE"
                or not isinstance(response, Mapping)
                or not isinstance(response.get("certificateId"), str)
                or not _CERT_ID.fullmatch(response["certificateId"])
                or response.get("certificateArn")
                   != f"arn:aws:iot:{region}:{account}:cert/{response['certificateId']}"):
            return None
        # Certificate PEM is public key material but is deliberately not emitted.
        return _event(record, actor, account, response["certificateArn"],
                      "request.iot_external_certificate_registered_active")
    job_id = request.get("jobId")
    if not isinstance(job_id, str) or not _NAME.fullmatch(job_id):
        return None
    # The document body is returned by the API but omitted from CloudTrail.
    return _event(record, actor, account, f"arn:aws:iot:{region}:{account}:job/{job_id}",
                  "request.iot_job_document_read")


def correlate_external_cert_policy(
    records: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    registered: dict[str, list[tuple[datetime, str, str, str, str]]] = {}
    attached: list[tuple[datetime, str, str, str, str, str, Mapping[str, Any]]] = []
    for record in records:
        if record.get("eventName") == "RegisterCertificateWithoutCA":
            event = normalize(record)
            if event is None:
                continue
            when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
            registered.setdefault(event["target.id"], []).append((
                when, event["account.id"], record["awsRegion"], event["actor.id"], event["event.id"]))
        elif record.get("eventName") == "AttachPolicy":
            common = _common(record)
            if common is None:
                continue
            account, region, actor, when, request = common
            target, policy = request.get("target"), request.get("policyName")
            if (not isinstance(target, str)
                    or not target.startswith(f"arn:aws:iot:{region}:{account}:cert/")
                    or not isinstance(policy, str) or not _NAME.fullmatch(policy)):
                continue
            attached.append((when, account, region, actor, target, policy, record))
    out = []
    for when, account, region, actor, target, policy, record in attached:
        for created, prev_account, prev_region, prev_actor, event_id in registered.get(target, []):
            if (account == prev_account and region == prev_region and actor == prev_actor
                    and created <= when <= created + timedelta(minutes=30)):
                event = _event(record, actor, account, target,
                               "request.iot_external_certificate_policy_attached")
                event["event.name"] = "IoTExternalCertificatePolicyAttached"
                event["correlation_evidence"] = {
                    "register_event_id": event_id, "attach_event_id": record["eventID"],
                    "policy_name": policy,
                }
                out.append(event)
                break
    return out
