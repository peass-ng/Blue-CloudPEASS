"""Bounded CodeBuild debug and source-auth correlations from management events.

Only event identifiers and the project ARN leave this module. Session tokens,
secret values, source URLs, S3 keys, and buildspecs never enter evidence.
"""

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,149}\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo is not None else None


def _common(record: Mapping[str, Any], source: str, name: str, read_only: bool):
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (record.get("eventSource") != source or record.get("eventName") != name
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not read_only
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or not isinstance(request, Mapping)
            or identity.get("accountId") not in (None, account)
            or not isinstance(identity.get("arn"), str)
            or not identity["arn"].startswith("arn:")
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or _time(record.get("eventTime")) is None):
        return None
    return account, region, identity["arn"], request, _time(record["eventTime"])


def _project(account: str, region: str, name: Any) -> str | None:
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        return None
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    return f"arn:{partition}:codebuild:{region}:{account}:project/{name}"


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    starts = []
    sessions = []
    source_updates = []
    secret_reads = []
    for record in records:
        source, name = record.get("eventSource"), record.get("eventName")
        if source == "codebuild.amazonaws.com" and name == "StartBuild":
            common = _common(record, source, name, False)
            if common is None:
                continue
            account, region, _, request, when = common
            response = record.get("responseElements")
            build = response.get("build") if isinstance(response, Mapping) else None
            debug = build.get("debugSession") if isinstance(build, Mapping) else None
            project = request.get("projectName")
            arn = _project(account, region, project)
            build_id = build.get("id") if isinstance(build, Mapping) else None
            if (request.get("debugSessionEnabled") is True and arn is not None
                    and isinstance(debug, Mapping) and debug.get("sessionEnabled") is True
                    and isinstance(build_id, str) and build_id.startswith(project + ":")
                    and _UUID.fullmatch(build_id[len(project) + 1:])
                    and build.get("projectName") == project):
                starts.append((when, account, region, build_id[len(project) + 1:], arn, record))
        elif source == "ssm.amazonaws.com" and name == "StartSession":
            common = _common(record, source, name, False)
            if common is None:
                continue
            account, region, actor, request, when = common
            response = record.get("responseElements")
            target = request.get("target")
            if (isinstance(target, str) and target.startswith("codebuild:")
                    and _UUID.fullmatch(target[len("codebuild:"):])
                    and isinstance(response, Mapping)
                    and isinstance(response.get("sessionId"), str)
                    and response["sessionId"]):
                sessions.append((when, account, region, actor, target[len("codebuild:"):], record))
        elif source == "codebuild.amazonaws.com" and name == "UpdateProject":
            common = _common(record, source, name, False)
            if common is None:
                continue
            account, region, actor, request, when = common
            response = record.get("responseElements")
            returned = response.get("project") if isinstance(response, Mapping) else None
            if not isinstance(returned, Mapping):
                continue
            project = returned.get("name")
            arn = _project(account, region, project)
            supplied = request.get("source")
            supplied_auth = supplied.get("auth") if isinstance(supplied, Mapping) else None
            returned_source = returned.get("source")
            returned_auth = returned_source.get("auth") if isinstance(returned_source, Mapping) else None
            secret = supplied_auth.get("resource") if isinstance(supplied_auth, Mapping) else None
            partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
            prefix = f"arn:{partition}:secretsmanager:{region}:{account}:secret:"
            if (arn is not None and request.get("name") in (project, arn)
                    and returned.get("arn") == arn
                    and isinstance(secret, str) and secret.startswith(prefix)
                    and len(secret) > len(prefix)
                    and supplied_auth.get("type") == "SECRETS_MANAGER"
                    and isinstance(returned_auth, Mapping)
                    and returned_auth.get("type") == "SECRETS_MANAGER"
                    and returned_auth.get("resource") == secret):
                source_updates.append((when, account, region, actor, secret, arn, record))
        elif source == "secretsmanager.amazonaws.com" and name == "GetSecretValue":
            common = _common(record, source, name, True)
            if common is None:
                continue
            account, region, actor, request, when = common
            secret = request.get("secretId")
            partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
            if isinstance(secret, str) and secret.startswith(f"arn:{partition}:secretsmanager:{region}:{account}:secret:"):
                secret_reads.append((when, account, region, actor, secret, record))

    output = []
    for when, account, region, actor, uuid, event in sessions:
        prior = [s for s in starts if s[1:4] == (account, region, uuid)
                 and timedelta(0) <= when - s[0] <= timedelta(minutes=30)]
        if prior:
            start = max(prior, key=lambda s: s[0])
            output.append({"cloud.provider": "aws", "event.source": "ssm.amazonaws.com",
                           "event.name": "CodeBuildDebugSessionStarted", "event.outcome": "success",
                           "event.id": event["eventID"], "event.time": event["eventTime"],
                           "account.id": account, "actor.id": actor, "target.id": start[4],
                           "request.codebuild_debug_session_started": True,
                           "correlation_evidence": {"start_build_event_id": start[5]["eventID"]}})
    for when, account, region, actor, secret, event in secret_reads:
        prior = [u for u in source_updates if u[1:5] == (account, region, actor, secret)
                 and timedelta(0) <= when - u[0] <= timedelta(hours=1)]
        if prior:
            update = max(prior, key=lambda u: u[0])
            output.append({"cloud.provider": "aws", "event.source": "secretsmanager.amazonaws.com",
                           "event.name": "CodeBuildSourceAuthSecretReadAfterUpdate", "event.outcome": "success",
                           "event.id": event["eventID"], "event.time": event["eventTime"],
                           "account.id": account, "actor.id": actor, "target.id": update[5],
                           "request.codebuild_source_auth_secret_read_after_update": True,
                           "correlation_evidence": {"update_project_event_id": update[6]["eventID"]}})
    return output
