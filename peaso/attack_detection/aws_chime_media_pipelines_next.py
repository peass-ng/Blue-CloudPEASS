"""Chime media pipeline control-plane signals and bounded live-read correlation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_FLAGS = {
    "CreateMediaCapturePipeline": "request.chime_media_capture_pipeline_created",
    "CreateMediaLiveConnectorPipeline": "request.chime_media_live_connector_created",
    "GetMediaPipeline": "request.chime_media_pipeline_read",
    "ListMediaPipelines": "request.chime_media_pipelines_listed",
    "DeleteMediaCapturePipeline": "request.chime_media_capture_pipeline_deleted",
    "DeleteMediaPipeline": "request.chime_media_pipeline_deleted",
}
_READS = {"GetMediaPipeline", "ListMediaPipelines"}


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def normalize_aws_chime_media_pipeline(record: Mapping[str, Any]) -> dict[str, Any] | None:
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

    pipeline_id = None
    if name in {"CreateMediaCapturePipeline", "CreateMediaLiveConnectorPipeline"}:
        response = record.get("responseElements")
        key = ("mediaCapturePipeline" if name == "CreateMediaCapturePipeline"
               else "mediaLiveConnectorPipeline")
        body = response.get(key) if isinstance(response, Mapping) else None
        if not isinstance(body, Mapping):
            return None
        pipeline_id = body.get("mediaPipelineId")
        if not isinstance(pipeline_id, str) or not _UUID.fullmatch(pipeline_id):
            return None
        expected = f"arn:aws:chime:{region}:{account}:media-pipeline/{pipeline_id}"
        if body.get("mediaPipelineArn") != expected:
            return None
        if name == "CreateMediaCapturePipeline":
            if (request.get("sourceType") != "ChimeSdkMeeting"
                    or request.get("sinkType") != "S3Bucket"
                    or body.get("sourceType") != "ChimeSdkMeeting"
                    or body.get("sinkType") != "S3Bucket"):
                return None
        else:
            sources, sinks = request.get("sources"), request.get("sinks")
            if (not isinstance(sources, list) or len(sources) != 1
                    or not isinstance(sinks, list) or len(sinks) != 1
                    or not isinstance(sources[0], Mapping)
                    or not isinstance(sinks[0], Mapping)
                    or sources[0].get("sourceType") != "ChimeSdkMeeting"
                    or sinks[0].get("sinkType") != "RTMP"
                    or not isinstance(sinks[0].get("rTMPConfiguration"), Mapping)
                    or not isinstance(sinks[0]["rTMPConfiguration"].get("url"), str)
                    or not sinks[0]["rTMPConfiguration"]["url"]
                    or body.get("sources") != sources or body.get("sinks") != sinks):
                return None
    elif name == "ListMediaPipelines":
        limit = request.get("maxResults")
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool)
                                  or not 1 <= limit <= 100):
            return None
    else:
        pipeline_id = request.get("mediaPipelineId")
        if not isinstance(pipeline_id, str) or not _UUID.fullmatch(pipeline_id):
            return None

    target = (f"arn:aws:chime:{region}:{account}:media-pipeline/{pipeline_id}"
              if pipeline_id else f"arn:aws:chime:{region}:{account}:media-pipeline/*")
    return {"cloud.provider": "aws", "event.source": "chime-sdk-media-pipelines.amazonaws.com",
            "event.name": name, "event.outcome": "success", "event.id": record["eventID"],
            "event.time": record["eventTime"], "account.id": account,
            "actor.id": identity["arn"], "target.id": target, _FLAGS[name]: True}


def correlate_aws_chime_live_pipeline_read(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = []
    for record in records:
        if record.get("eventName") not in {"CreateMediaLiveConnectorPipeline", "GetMediaPipeline"}:
            continue
        normalized = normalize_aws_chime_media_pipeline(record)
        if normalized is None:
            continue
        when = _time(record.get("eventTime"))
        if when is None:
            continue
        ordered.append((when, 0 if record["eventName"] == "CreateMediaLiveConnectorPipeline" else 1,
                        normalized, record))
    ordered.sort(key=lambda item: (item[0], item[1]))
    creators: dict[tuple[str, str, str], tuple[datetime, Mapping[str, Any]]] = {}
    matches = []
    for when, _, normalized, record in ordered:
        key = (normalized["account.id"], record["awsRegion"], normalized["target.id"])
        if record["eventName"] == "CreateMediaLiveConnectorPipeline":
            creators[key] = (when, record)
            continue
        created = creators.get(key)
        if created is None or not timedelta(0) <= when - created[0] <= timedelta(hours=24):
            continue
        correlated = dict(normalized)
        correlated.pop("request.chime_media_pipeline_read", None)
        matches.append({**correlated, "request.chime_live_connector_pipeline_read": True,
                        "correlation_evidence": {"creator_event_id": created[1]["eventID"]}})
    return matches
