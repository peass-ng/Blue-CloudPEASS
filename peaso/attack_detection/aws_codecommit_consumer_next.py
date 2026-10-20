"""Join a transferred CodeCommit GitPush revision to a real CodeBuild start.

The join proves that a build started with the pushed revision. It does not
infer build completion, malicious intent, or a privilege delta from CloudTrail.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_ROLE = re.compile(r"arn:aws(?:-us-gov|-cn)?:iam::[0-9]{12}:role/.+\Z")


def _common(record: Mapping[str, Any], source: str, name: str):
    if (record.get("eventSource") != source or record.get("eventName") != name
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, identity = (record.get("recipientAccountId"),
                                 record.get("awsRegion"), record.get("userIdentity"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    return account, region, identity["arn"], when


def _source_and_build(pipeline: Mapping[str, Any]):
    sources, projects = set(), set()
    stages = pipeline.get("stages")
    if not isinstance(stages, list):
        return sources, projects
    for stage in stages:
        if not isinstance(stage, Mapping) or not isinstance(stage.get("actions"), list):
            continue
        for action in stage["actions"]:
            if not isinstance(action, Mapping):
                continue
            kind, config = action.get("actionTypeId"), action.get("configuration")
            if not isinstance(kind, Mapping) or not isinstance(config, Mapping):
                continue
            if kind.get("category") == "Source" and kind.get("provider") == "CodeCommit":
                repo, branch = config.get("RepositoryName"), config.get("BranchName")
                if (isinstance(repo, str) and _NAME.fullmatch(repo)
                        and isinstance(branch, str) and _NAME.fullmatch(branch)):
                    sources.add((repo, branch))
            elif kind.get("category") == "Build" and kind.get("provider") == "CodeBuild":
                project = config.get("ProjectName")
                if isinstance(project, str) and _NAME.fullmatch(project):
                    projects.add(project)
    return sources, projects


def _canonical(build: Mapping[str, Any], account: str, actor: str, project: str,
               flag: str, name: str, evidence: Mapping[str, str]):
    return {"cloud.provider": "aws", "event.source": "codebuild.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": build["eventID"], "event.time": build["eventTime"],
            "account.id": account, "actor.id": actor, "target.id": project,
            flag: True, "correlation_evidence": dict(evidence)}


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    pushes = defaultdict(list)
    definitions = defaultdict(list)
    starts = defaultdict(list)
    builds = []
    for record in records:
        source, name = record.get("eventSource"), record.get("eventName")
        if (source, name) == ("codecommit.amazonaws.com", "GitPush"):
            common = _common(record, source, name)
            extra, request = record.get("additionalEventData"), record.get("requestParameters")
            if (common is None or not isinstance(extra, Mapping)
                    or extra.get("dataTransferred") is not True
                    or not isinstance(request, Mapping)
                    or not isinstance(request.get("references"), list)):
                continue
            repo = extra.get("repositoryName")
            if not isinstance(repo, str) or not _NAME.fullmatch(repo):
                continue
            account, region, actor, when = common
            for ref in request["references"]:
                if not isinstance(ref, Mapping):
                    continue
                fullname, sha = ref.get("ref"), ref.get("commit")
                if (not isinstance(fullname, str) or not fullname.startswith("refs/heads/")
                        or not _NAME.fullmatch(fullname[11:])
                        or not isinstance(sha, str) or not _SHA.fullmatch(sha)):
                    continue
                pushes[(account, region, sha.lower())].append(
                    (when, actor, repo, fullname[11:], record))
        elif source == "codepipeline.amazonaws.com" and name in {"CreatePipeline", "UpdatePipeline"}:
            common = _common(record, source, name)
            request, response = record.get("requestParameters"), record.get("responseElements")
            if common is None or not isinstance(request, Mapping) or not isinstance(response, Mapping):
                continue
            pipeline, result = request.get("pipeline"), response.get("pipeline")
            if not isinstance(pipeline, Mapping) or not isinstance(result, Mapping):
                continue
            pname = pipeline.get("name")
            if not isinstance(pname, str) or not _NAME.fullmatch(pname) or result.get("name") != pname:
                continue
            sources, projects = _source_and_build(pipeline)
            definitions[(common[0], common[1], pname)].append(
                (common[3], sources, projects, record))
        elif (source, name) == ("codepipeline.amazonaws.com", "StartPipelineExecution"):
            common = _common(record, source, name)
            request, response = record.get("requestParameters"), record.get("responseElements")
            if common is None or not isinstance(request, Mapping) or not isinstance(response, Mapping):
                continue
            pname, execution = request.get("name"), response.get("pipelineExecutionId")
            if (isinstance(pname, str) and _NAME.fullmatch(pname)
                    and isinstance(execution, str) and execution):
                starts[(common[0], common[1], pname)].append((common[3], record))
        elif (source, name) == ("codebuild.amazonaws.com", "StartBuild"):
            common = _common(record, source, name)
            request, response = record.get("requestParameters"), record.get("responseElements")
            if common is None or not isinstance(request, Mapping) or not isinstance(response, Mapping):
                continue
            build = response.get("build")
            if not isinstance(build, Mapping):
                continue
            project, bsource, role = request.get("projectName"), build.get("source"), build.get("serviceRole")
            if (not isinstance(project, str) or not _NAME.fullmatch(project)
                    or build.get("projectName") != project
                    or not isinstance(bsource, Mapping)
                    or not isinstance(role, str) or not _ROLE.fullmatch(role)):
                continue
            builds.append((common, request, build, record))

    output = []
    for (account, region, actor, build_time), request, build, event in builds:
        project = request["projectName"]
        bsource = build["source"]
        if bsource.get("type") == "CODECOMMIT":
            sha = request.get("sourceVersion")
            location = bsource.get("location")
            if not isinstance(sha, str) or not _SHA.fullmatch(sha) or not isinstance(location, str):
                continue
            for (acct, reg, ref_sha), candidates in pushes.items():
                if (acct, reg, ref_sha) != (account, region, sha.lower()):
                    continue
                for push_time, pusher, repo, branch, push in candidates:
                    if (location != f"https://git-codecommit.{region}.amazonaws.com/v1/repos/{repo}"
                            or not timedelta(0) <= build_time-push_time <= timedelta(hours=24)):
                        continue
                    output.append(_canonical(event, account, pusher, project,
                        "request.codecommit_direct_revision_build_started",
                        "CodeCommitDirectRevisionBuildStarted",
                        {"git_push_event_id": push["eventID"], "build_start_event_id": event["eventID"]}))
                    break
        elif bsource.get("type") == "CODEPIPELINE":
            sha = build.get("resolvedSourceVersion")
            initiator = build.get("initiator")
            if (not isinstance(sha, str) or not _SHA.fullmatch(sha)
                    or not isinstance(initiator, str) or not initiator.startswith("codepipeline/")):
                continue
            pname = initiator[len("codepipeline/"):]
            if not _NAME.fullmatch(pname):
                continue
            defs = [d for d in definitions.get((account, region, pname), [])
                    if d[0] <= build_time and project in d[2]]
            if not defs:
                continue
            definition = max(defs, key=lambda d: d[0])
            pipeline_starts = [s for s in starts.get((account, region, pname), [])
                               if timedelta(0) <= build_time-s[0] <= timedelta(hours=1)]
            if not pipeline_starts:
                continue
            for push_time, pusher, repo, branch, push in pushes.get((account, region, sha.lower()), []):
                if ((repo, branch) not in definition[1]
                        or not timedelta(0) <= build_time-push_time <= timedelta(hours=24)):
                    continue
                eligible_starts = [s for s in pipeline_starts if s[0] >= push_time]
                if not eligible_starts:
                    continue
                started = max(eligible_starts, key=lambda s: s[0])
                output.append(_canonical(event, account, pusher, project,
                    "request.codecommit_pipeline_revision_build_started",
                    "CodeCommitPipelineRevisionBuildStarted",
                    {"git_push_event_id": push["eventID"],
                     "pipeline_definition_event_id": definition[3]["eventID"],
                     "pipeline_start_event_id": started[1]["eventID"],
                     "build_start_event_id": event["eventID"]}))
                break
    return output
