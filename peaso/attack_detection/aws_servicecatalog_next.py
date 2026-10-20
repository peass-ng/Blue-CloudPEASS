"""Service Catalog launch-role and portfolio signals from management events.

ProvisionProduct is asynchronous. The artifact/provision pair reports the
accepted request path only; stack success needs external effect evidence.
"""
from collections.abc import Mapping
from datetime import datetime, timedelta
import json
import re
from typing import Any
from uuid import UUID

SOURCE = "servicecatalog.amazonaws.com"
NAMES = {"CreateConstraint", "AssociatePrincipalWithPortfolio",
         "CreateProvisioningArtifact", "ProvisionProduct",
         "GetProvisionedProductOutputs"}
PRODUCT = re.compile(r"prod-[a-z0-9]{8,32}\Z")
ARTIFACT = re.compile(r"pa-[a-z0-9]{8,32}\Z")
RECORD = re.compile(r"rec-[a-z0-9]{8,32}\Z")
PORTFOLIO = re.compile(r"port-[a-z0-9]{8,32}\Z")
PROVISIONED = re.compile(r"pp-[a-z0-9]{8,32}\Z")
REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try: result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError: return None
    return result if result.tzinfo is not None else None


def project(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Keep only nonsecret exact identifiers used by detections."""
    name = record.get("eventName")
    if (record.get("eventSource") != SOURCE or name not in NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "GetProvisionedProductOutputs")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or identity.get("accountId") != account):
        return None
    actor = identity.get("arn")
    if (not isinstance(actor, str) or not actor.startswith((
            f"arn:aws:iam::{account}:", f"arn:aws:sts::{account}:"))):
        return None
    try: UUID(record.get("eventID"))
    except (TypeError, ValueError, AttributeError): return None
    when = _time(record.get("eventTime"))
    if when is None: return None
    response = record.get("responseElements")
    if response is not None and not isinstance(response, Mapping): return None
    response = response or {}
    result = {"name":name,"account":account,"region":region,"actor":actor,
              "event_id":record["eventID"],"event_time":when}
    product = request.get("productId")
    portfolio = request.get("portfolioId")
    if name == "CreateConstraint":
        if (not isinstance(product,str) or not PRODUCT.fullmatch(product)
                or not isinstance(portfolio,str) or not PORTFOLIO.fullmatch(portfolio)
                or request.get("type") != "LAUNCH"):
            return None
        params = request.get("parameters")
        if not isinstance(params,str) or len(params)>8192: return None
        try: role = json.loads(params).get("RoleArn")
        except (ValueError,AttributeError): return None
        detail = response.get("constraintDetail")
        if (not isinstance(role,str) or not re.fullmatch(
                rf"arn:aws:iam::{account}:role/[A-Za-z0-9_+=,.@/-]+",role)
                or not isinstance(detail,Mapping) or detail.get("type")!="LAUNCH"
                or detail.get("productId")!=product or detail.get("portfolioId")!=portfolio
                or not isinstance(detail.get("constraintId"),str)):
            return None
        result.update(product=product,portfolio=portfolio,role=role,variant="launch_role_constraint")
    elif name == "AssociatePrincipalWithPortfolio":
        principal,kind=request.get("principalARN"),request.get("principalType")
        if not isinstance(portfolio,str) or not PORTFOLIO.fullmatch(portfolio):return None
        if kind=="IAM":
            if (not isinstance(principal,str) or not re.fullmatch(
                    rf"arn:aws:iam::{account}:(?:role|user|group)/[A-Za-z0-9_+=,.@/-]+",principal)):
                return None
            variant="principal_granted"
        elif kind=="IAM_PATTERN":
            if (not isinstance(principal,str) or not re.fullmatch(
                    r"arn:aws:iam:::(?:role|user|group)/[A-Za-z0-9_+=,.@/*?-]+",principal)
                    or not any(c in principal for c in "*?")):
                return None
            variant="principal_pattern_granted"
        else:return None
        result.update(portfolio=portfolio,principal=principal,variant=variant)
    elif name == "CreateProvisioningArtifact":
        detail=response.get("provisioningArtifactDetail")
        artifact=detail.get("id") if isinstance(detail,Mapping) else None
        if (not isinstance(product,str) or not PRODUCT.fullmatch(product)
                or not isinstance(artifact,str) or not ARTIFACT.fullmatch(artifact)):
            return None
        result.update(product=product,artifact=artifact)
    elif name == "ProvisionProduct":
        artifact=request.get("provisioningArtifactId")
        detail=response.get("recordDetail")
        record_id=detail.get("recordId") if isinstance(detail,Mapping) else None
        if (not isinstance(product,str) or not PRODUCT.fullmatch(product)
                or not isinstance(artifact,str) or not ARTIFACT.fullmatch(artifact)
                or not isinstance(record_id,str) or not RECORD.fullmatch(record_id)
                or detail.get("productId") != product
                or detail.get("provisioningArtifactId") != artifact):return None
        result.update(product=product,artifact=artifact,record_id=record_id)
    else:
        provisioned=request.get("provisionedProductId")
        if not isinstance(provisioned,str) or not PROVISIONED.fullmatch(provisioned):return None
        result.update(provisioned=provisioned,variant="outputs_accessed")
    return result


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    e=project(record)
    if e is None or "variant" not in e:return None
    target=(f"servicecatalog-portfolio:{e['region']}:{e['account']}:{e['portfolio']}"
            if "portfolio" in e else f"servicecatalog-product:{e['region']}:{e['account']}:{e['provisioned']}")
    return {"cloud.provider":"aws","event.source":SOURCE,"event.name":e['name'],
            "event.outcome":"success","event.id":e['event_id'],"event.time":record["eventTime"],"account.id":e['account'],
            "actor.id":e['actor'],"cloud.region":e['region'],"target.id":target,
            "request.servicecatalog_"+e['variant']:True}


def correlate(records: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Pair exact same-actor artifact publication and provision request."""
    projected=[e for record in records if (e:=project(record)) is not None]
    creations=[e for e in projected if e['name']=="CreateProvisioningArtifact"]
    output=[]
    for provision in (e for e in projected if e['name']=="ProvisionProduct"):
        if not any(all(created[k]==provision[k] for k in
                       ("account","region","actor","product","artifact"))
                   and created['event_time']<provision['event_time']
                   <=created['event_time']+timedelta(hours=1)
                   for created in creations):continue
        output.append({"cloud.provider":"aws","event.source":SOURCE,
            "event.name":"ProvisionProduct","event.outcome":"success",
            "event.id":provision['event_id'],"event.time":provision['event_time'].isoformat(),"account.id":provision['account'],
            "actor.id":provision['actor'],"cloud.region":provision['region'],
            "target.id":f"servicecatalog-product:{provision['region']}:{provision['account']}:{provision['product']}",
            "request.servicecatalog_artifact_created_then_provisioned":True})
    return output
