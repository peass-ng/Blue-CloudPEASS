"""CodePipeline mutation, rollback, stage override, source, and custom job signals.

Buildspecs, source object keys, S3 bodies, custom job IDs, and job nonces are
used only for matching. Canonical evidence contains event IDs and names.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_NAME = re.compile(r"[A-Za-z0-9.@_-]{1,100}\Z")
_PROJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,149}\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _common(record: Mapping[str, Any], source: str, category: str = "Management"):
    account, region, identity, request = (record.get("recipientAccountId"), record.get("awsRegion"),
                                           record.get("userIdentity"), record.get("requestParameters"))
    if (record.get("eventSource") != source or record.get("eventCategory") != category
            or record.get("eventType") != "AwsApiCall" or record.get("managementEvent") is not (category == "Management")
            or record.get("readOnly") is not False or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or _time(record.get("eventTime")) is None):
        return None
    return account, region, identity["arn"], request, _time(record["eventTime"])


def _canonical(record: Mapping[str, Any], account: str, actor: str, target: str,
               flag: str, name: str | None = None, evidence: Mapping[str, str] | None = None):
    value = {"cloud.provider": "aws", "event.source": record["eventSource"],
             "event.name": name or record["eventName"], "event.outcome": "success",
             "event.id": record["eventID"], "event.time": record["eventTime"],
             "account.id": account, "actor.id": actor, "target.id": target, flag: True}
    if evidence:
        value["correlation_evidence"] = dict(evidence)
    return value


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventName") not in {"OverrideStageCondition", "RollbackStage"}:
        return None
    common = _common(record, "codepipeline.amazonaws.com")
    if common is None:
        return None
    account, region, actor, request, _ = common
    pipeline, stage = request.get("pipelineName"), request.get("stageName")
    if not isinstance(pipeline, str) or not _NAME.fullmatch(pipeline) or not isinstance(stage, str) or not _NAME.fullmatch(stage):
        return None
    response = record.get("responseElements")
    if record["eventName"] == "OverrideStageCondition":
        execution = request.get("pipelineExecutionId")
        if (request.get("conditionType") not in {"BEFORE_ENTRY", "ON_SUCCESS"}
                or not isinstance(execution, str) or not _UUID.fullmatch(execution)):
            return None
        return _canonical(record, account, actor, pipeline,
                          "request.pipeline_stage_condition_overridden")
    target = request.get("targetPipelineExecutionId")
    new = response.get("pipelineExecutionId") if isinstance(response, Mapping) else None
    if (not isinstance(target, str) or not _UUID.fullmatch(target)
            or not isinstance(new, str) or not _UUID.fullmatch(new) or new == target):
        return None
    return _canonical(record, account, actor, pipeline,
                      "request.pipeline_prior_stage_revision_rollback_submitted")


def _source_pairs(pipeline: Mapping[str, Any]):
    for stage in pipeline.get("stages", []) if isinstance(pipeline.get("stages"), list) else []:
        if not isinstance(stage, Mapping):
            continue
        for action in stage.get("actions", []) if isinstance(stage.get("actions"), list) else []:
            if not isinstance(action, Mapping) or not isinstance(action.get("actionTypeId"), Mapping):
                continue
            action_type = action["actionTypeId"]
            config = action.get("configuration")
            if (action_type.get("category") == "Source" and action_type.get("provider") == "S3"
                    and isinstance(config, Mapping)):
                bucket, key = config.get("S3Bucket"), config.get("S3ObjectKey")
                if isinstance(bucket, str) and bucket and isinstance(key, str) and key:
                    yield bucket, key


def _build_projects(pipeline: Mapping[str, Any]):
    for stage in pipeline.get("stages", []) if isinstance(pipeline.get("stages"), list) else []:
        if not isinstance(stage, Mapping):
            continue
        for action in stage.get("actions", []) if isinstance(stage.get("actions"), list) else []:
            if not isinstance(action, Mapping) or not isinstance(action.get("actionTypeId"), Mapping):
                continue
            action_type = action["actionTypeId"]
            config = action.get("configuration")
            if (action_type.get("category") == "Build" and action_type.get("provider") == "CodeBuild"
                    and isinstance(config, Mapping) and len(config) > 1
                    and isinstance(config.get("ProjectName"), str)):
                yield config["ProjectName"]


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    project_updates = []
    pipeline_updates = []
    pipeline_sources = []
    starts = []
    puts = []
    acknowledged = []
    completed = []
    for record in records:
        name, source = record.get("eventName"), record.get("eventSource")
        if name == "PutObject" and source == "s3.amazonaws.com":
            common = _common(record, source, "Data")
            if common is None:
                continue
            account, region, actor, request, when = common
            bucket, key = request.get("bucketName"), request.get("key")
            if isinstance(bucket, str) and bucket and isinstance(key, str) and key:
                puts.append((when, account, region, actor, bucket, key, record))
            continue
        if source not in {"codepipeline.amazonaws.com", "codebuild.amazonaws.com"}:
            continue
        common = _common(record, source)
        if common is None:
            continue
        account, region, actor, request, when = common
        response = record.get("responseElements")
        response = response if isinstance(response, Mapping) else {}
        if name == "UpdateProject" and source == "codebuild.amazonaws.com":
            project, supplied = response.get("project"), request.get("source")
            if not isinstance(project, Mapping) or not isinstance(supplied, Mapping):
                continue
            pname = project.get("name")
            partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
            arn = f"arn:{partition}:codebuild:{region}:{account}:project/{pname}"
            if (isinstance(pname, str) and _PROJECT.fullmatch(pname)
                    and request.get("name") in {pname, arn}
                    and project.get("arn") == arn
                    and supplied.get("type") == "CODEPIPELINE"
                    and isinstance(supplied.get("buildspec"), str) and bool(supplied["buildspec"])):
                project_updates.append((when, account, region, actor, pname, record))
        elif name in {"CreatePipeline", "UpdatePipeline"} and source == "codepipeline.amazonaws.com":
            pipeline, result = request.get("pipeline"), response.get("pipeline")
            if not isinstance(pipeline, Mapping) or not isinstance(result, Mapping):
                continue
            pname = pipeline.get("name")
            if not isinstance(pname, str) or not _NAME.fullmatch(pname) or result.get("name") != pname:
                continue
            pipeline_sources.append((when, account, region, pname, set(_source_pairs(pipeline)), record))
            if name == "UpdatePipeline":
                projects = set(_build_projects(pipeline))
                if projects:
                    pipeline_updates.append((when, account, region, actor, pname, projects, record))
        elif name == "StartPipelineExecution" and source == "codepipeline.amazonaws.com":
            pname, execution = request.get("name"), response.get("pipelineExecutionId")
            if isinstance(pname, str) and _NAME.fullmatch(pname) and isinstance(execution, str) and _UUID.fullmatch(execution):
                starts.append((when, account, region, actor, pname, record))
        elif name == "AcknowledgeJob" and source == "codepipeline.amazonaws.com":
            job = request.get("jobId")
            if isinstance(job, str) and _UUID.fullmatch(job) and response.get("status") == "InProgress":
                acknowledged.append((when, account, region, actor, job, record))
        elif name == "PutJobSuccessResult" and source == "codepipeline.amazonaws.com":
            job = request.get("jobId")
            if isinstance(job, str) and _UUID.fullmatch(job):
                completed.append((when, account, region, actor, job, record))
    output = []
    consumed_updates: set[str] = set()
    consumed_puts: set[str] = set()
    for when, account, region, actor, pname, event in sorted(starts, key=lambda x: x[0]):
        prior_updates = [u for u in pipeline_updates if u[1:5] == (account, region, actor, pname)
                         and timedelta(0) <= when-u[0] <= timedelta(hours=1)
                         and u[6]["eventID"] not in consumed_updates]
        for update in prior_updates:
            project = [u for u in project_updates if u[1:4] == (account, region, actor)
                       and u[4] in update[5] and timedelta(0) <= update[0]-u[0] <= timedelta(hours=1)]
            if project:
                closest = max(project, key=lambda x: x[0])
                output.append(_canonical(event, account, actor, pname,
                    "request.pipeline_project_mutation_executed", "CodePipelineProjectMutationExecuted",
                    {"project_update_event_id": closest[5]["eventID"],
                     "pipeline_update_event_id": update[6]["eventID"]}))
                consumed_updates.add(update[6]["eventID"])
                break
        data = [p for p in puts if p[1:3] == (account, region) and timedelta(0) <= when-p[0] <= timedelta(hours=1)]
        definitions = [d for d in pipeline_sources if d[1:4] == (account, region, pname) and d[0] <= when]
        if data and definitions:
            definition = max(definitions, key=lambda x: x[0])
            matches = [p for p in data if (p[4], p[5]) in definition[4]
                       and p[6]["eventID"] not in consumed_puts]
            if matches:
                put = max(matches, key=lambda x: x[0])
                output.append(_canonical(event, account, actor, pname,
                    "request.pipeline_s3_source_overwrite_before_start", "CodePipelineS3SourceOverwriteBeforeStart",
                    {"source_put_event_id": put[6]["eventID"],
                     "pipeline_definition_event_id": definition[5]["eventID"]}))
                consumed_puts.add(put[6]["eventID"])
    for when, account, region, actor, job, event in completed:
        prior = [a for a in acknowledged if a[1:3] == (account, region) and a[4] == job
                 and a[3] != actor and timedelta(0) <= when-a[0] <= timedelta(minutes=30)]
        if prior:
            acknowledgement = max(prior, key=lambda x: x[0])
            output.append(_canonical(event, account, actor, "custom-action-job",
                "request.pipeline_custom_job_cross_actor_success", "CodePipelineCustomJobCrossActorSuccess",
                {"acknowledge_event_id": acknowledgement[5]["eventID"]}))
    return output
