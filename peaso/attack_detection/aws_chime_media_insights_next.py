"""Chime Media Insights role binding and pipeline configuration signals."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_NAME = re.compile(r"[A-Za-z0-9._-]{2,64}\Z")
_FLAGS = {
    "CreateMediaInsightsPipelineConfiguration": "request.chime_insights_configuration_role_bound",
    "UpdateMediaInsightsPipelineConfiguration": "request.chime_insights_configuration_role_updated",
    "GetMediaInsightsPipelineConfiguration": "request.chime_insights_configuration_read",
    "ListMediaInsightsPipelineConfigurations": "request.chime_insights_configurations_listed",
    "CreateMediaInsightsPipeline": "request.chime_insights_pipeline_created",
    "DeleteMediaInsightsPipelineConfiguration": "request.chime_insights_configuration_deleted",
}
_READS = {"GetMediaInsightsPipelineConfiguration", "ListMediaInsightsPipelineConfigurations"}
_CONFIG = "media-insights-pipeline-configuration"


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def _config_arn(identifier: Any, account: str, region: str) -> str | None:
    prefix = f"arn:aws:chime:{region}:{account}:{_CONFIG}/"
    if isinstance(identifier, str) and identifier.startswith(prefix):
        return identifier if _NAME.fullmatch(identifier[len(prefix):]) else None
    return None


def _config_identifier(identifier: Any, account: str, region: str) -> str | None:
    arn = _config_arn(identifier, account, region)
    if arn is not None:
        return arn
    return identifier if isinstance(identifier, str) and _UUID.fullmatch(identifier) else None


def _role(value: Any, account: str) -> bool:
    return (isinstance(value, str)
            and value.startswith(f"arn:aws:iam::{account}:role/")
            and bool(value.split(":role/", 1)[-1]))


def normalize_aws_chime_media_insights(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (name not in _FLAGS or record.get("eventSource") != "chime-sdk-media-pipelines.amazonaws.com"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name in _READS)
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or identity.get("accountId") not in (None, account)
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or _time(record.get("eventTime")) is None):
        return None

    extra = {}
    if name in {"CreateMediaInsightsPipelineConfiguration", "UpdateMediaInsightsPipelineConfiguration"}:
        role = request.get("resourceAccessRoleArn")
        elements = request.get("elements")
        response = record.get("responseElements")
        body = response.get("mediaInsightsPipelineConfiguration") if isinstance(response, Mapping) else None
        if (not _role(role, account) or not isinstance(elements, list) or not elements
                or not all(isinstance(element, Mapping) and isinstance(element.get("type"), str)
                           for element in elements)
                or not isinstance(body, Mapping)
                or not isinstance(body.get("mediaInsightsPipelineConfigurationId"), str)
                or not _UUID.fullmatch(body["mediaInsightsPipelineConfigurationId"])):
            return None
        name_value = body.get("mediaInsightsPipelineConfigurationName")
        target = (f"arn:aws:chime:{region}:{account}:{_CONFIG}/{name_value}"
                  if isinstance(name_value, str) and _NAME.fullmatch(name_value) else None)
        if (body.get("mediaInsightsPipelineConfigurationArn") != target
                or body.get("resourceAccessRoleArn") != role
                or body.get("elements") != elements):
            return None
        if (name == "CreateMediaInsightsPipelineConfiguration"
                and request.get("mediaInsightsPipelineConfigurationName") != name_value):
            return None
        if (name == "UpdateMediaInsightsPipelineConfiguration"
                and _config_identifier(request.get("identifier"), account, region)
                not in {target, body["mediaInsightsPipelineConfigurationId"]}):
            return None
        extra["request.chime_insights_resource_role_arn"] = role
    elif name == "ListMediaInsightsPipelineConfigurations":
        limit = request.get("maxResults")
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool)
                                  or not 1 <= limit <= 100):
            return None
        target = f"arn:aws:chime:{region}:{account}:{_CONFIG}/*"
    elif name in {"GetMediaInsightsPipelineConfiguration",
                  "DeleteMediaInsightsPipelineConfiguration"}:
        target = _config_identifier(request.get("identifier"), account, region)
        if target is None:
            return None
    else:
        config = _config_arn(request.get("mediaInsightsPipelineConfigurationArn"), account, region)
        response = record.get("responseElements")
        body = response.get("mediaInsightsPipeline") if isinstance(response, Mapping) else None
        runtime = request.get("kinesisVideoStreamSourceRuntimeConfiguration")
        if (config is None or not isinstance(body, Mapping)
                or body.get("mediaInsightsPipelineConfigurationArn") != config
                or not isinstance(body.get("mediaPipelineId"), str)
                or not _UUID.fullmatch(body["mediaPipelineId"])
                or not isinstance(runtime, Mapping)
                or runtime.get("mediaEncoding") != "pcm"
                or not isinstance(runtime.get("streams"), list) or not runtime["streams"]):
            return None
        target = f"arn:aws:chime:{region}:{account}:media-pipeline/{body['mediaPipelineId']}"
        if body.get("mediaPipelineArn") != target:
            return None
        extra["request.chime_insights_configuration_arn"] = config

    return {"cloud.provider": "aws", "event.source": "chime-sdk-media-pipelines.amazonaws.com",
            "event.name": name, "event.outcome": "success", "event.id": record["eventID"],
            "event.time": record["eventTime"], "account.id": account,
            "actor.id": identity["arn"], "target.id": target, _FLAGS[name]: True, **extra}


def correlate_aws_chime_media_insights(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = []
    for record in records:
        if record.get("eventName") not in {"CreateMediaInsightsPipelineConfiguration",
                                           "UpdateMediaInsightsPipelineConfiguration",
                                           "CreateMediaInsightsPipeline"}:
            continue
        normalized = normalize_aws_chime_media_insights(record)
        if normalized is None:
            continue
        when = _time(record.get("eventTime"))
        if when is None:
            continue
        priority = {"CreateMediaInsightsPipelineConfiguration": 0,
                    "UpdateMediaInsightsPipelineConfiguration": 1,
                    "CreateMediaInsightsPipeline": 2}[record["eventName"]]
        ordered.append((when, priority, normalized, record))
    ordered.sort(key=lambda item: (item[0], item[1]))
    created: dict[tuple[str, str, str], tuple[datetime, dict[str, Any]]] = {}
    changed: dict[tuple[str, str, str], tuple[datetime, dict[str, Any]]] = {}
    matches = []
    for when, _, normalized, record in ordered:
        name = record["eventName"]
        config = (normalized.get("request.chime_insights_configuration_arn")
                  if name == "CreateMediaInsightsPipeline" else normalized["target.id"])
        key = (normalized["account.id"], record["awsRegion"], config)
        if name == "CreateMediaInsightsPipelineConfiguration":
            created[key] = (when, normalized)
        elif name == "UpdateMediaInsightsPipelineConfiguration":
            earlier = created.get(key)
            if (earlier is not None and timedelta(0) <= when - earlier[0] <= timedelta(hours=24)
                    and earlier[1]["request.chime_insights_resource_role_arn"]
                    != normalized["request.chime_insights_resource_role_arn"]):
                changed[key] = (when, normalized)
                derived = dict(normalized)
                derived.pop("request.chime_insights_configuration_role_updated", None)
                matches.append({**derived, "request.chime_insights_role_rebound": True,
                                "correlation_evidence": {"creator_event_id": earlier[1]["event.id"]}})
        else:
            earlier = changed.get(key)
            if earlier is None or not timedelta(0) <= when - earlier[0] <= timedelta(hours=24):
                continue
            derived = dict(normalized)
            derived.pop("request.chime_insights_pipeline_created", None)
            matches.append({**derived, "request.chime_insights_pipeline_after_role_rebind": True,
                            "correlation_evidence": {"rebind_event_id": earlier[1]["event.id"]}})
    return matches
