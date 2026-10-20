"""Correlate AppConfig hosted-version creation, deployment and older reads.

Content is deliberately excluded from the normalized event. A successful API
call does not establish malicious intent or that a consumer used the content.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_ID = re.compile(r"[A-Za-z0-9_-]{1,50}\Z")
_CONFIG_ARN = re.compile(
    r"arn:aws(?:-us-gov|-cn)?:appconfig:([^:]+):([0-9]{12}):"
    r"application/([A-Za-z0-9_-]+)/environment/([A-Za-z0-9_-]+)/"
    r"configuration/([A-Za-z0-9_-]+)\Z")


def _common(record: Mapping[str, Any], name: str, read_only: bool):
    if (record.get("eventSource") != "appconfig.amazonaws.com"
            or record.get("eventName") != name
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not read_only
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, identity, request = (record.get("recipientAccountId"),
        record.get("awsRegion"), record.get("userIdentity"), record.get("requestParameters"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
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
    app, profile = request.get("applicationId"), request.get("configurationProfileId")
    if (not isinstance(app, str) or not _ID.fullmatch(app)
            or not isinstance(profile, str) or not _ID.fullmatch(profile)):
        return None
    return account, region, identity["arn"], when, app, profile, request


def _version(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 < value < 100000000:
        return value
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        number = int(value)
        return number if 0 < number < 100000000 else None
    return None


def _canonical(record: Mapping[str, Any], actor: str, target: str,
               name: str, flag: str, evidence: Mapping[str, str]):
    return {"cloud.provider": "aws", "event.source": "appconfig.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": record["recipientAccountId"], "actor.id": actor,
            "target.id": target, flag: True,
            "correlation_evidence": dict(evidence)}


def _data_common(record: Mapping[str, Any], name: str, read_only: bool):
    if (record.get("eventSource") != "appconfig.amazonaws.com"
            or record.get("eventName") != name
            or record.get("eventCategory") != "Data"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not False
            or record.get("readOnly") is not read_only
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
    resources = record.get("resources")
    if not isinstance(resources, list):
        return None
    arns = [r.get("ARN") for r in resources if isinstance(r, Mapping)
            and r.get("type") == "AWS::AppConfig::Configuration"
            and r.get("accountId") in (None, account)]
    if len(arns) != 1 or not isinstance(arns[0], str):
        return None
    match = _CONFIG_ARN.fullmatch(arns[0])
    if match is None or match.group(1) != region or match.group(2) != account:
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    return account, region, identity["arn"], when, arns[0], match.groups()[2:]


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    creations = []
    deployments = []
    reads = []
    data_sessions = []
    data_retrievals = []
    for record in records:
        name = record.get("eventName")
        if name in {"StartConfigurationSession", "GetLatestConfiguration"}:
            common = _data_common(record, name, name == "GetLatestConfiguration")
            request = record.get("requestParameters")
            if common is None or not isinstance(request, Mapping):
                continue
            account, region, actor, when, arn, ids = common
            if name == "StartConfigurationSession":
                if (request.get("applicationIdentifier"),
                        request.get("environmentIdentifier"),
                        request.get("configurationProfileIdentifier")) == ids:
                    data_sessions.append((when, account, region, actor, arn, record))
            elif isinstance(request.get("configurationToken"), str) and request["configurationToken"]:
                data_retrievals.append((when, account, region, actor, arn, record))
            continue
        if name == "CreateHostedConfigurationVersion":
            common = _common(record, name, False)
            response = record.get("responseElements")
            if common is None or not isinstance(response, Mapping):
                continue
            account, region, actor, when, app, profile, request = common
            version = _version(response.get("versionNumber"))
            if (version is None or response.get("applicationId") != app
                    or response.get("configurationProfileId") != profile
                    or not isinstance(request.get("contentType"), str)):
                continue
            creations.append((when, account, region, actor, app, profile, version, record))
        elif name == "StartDeployment":
            common = _common(record, name, False)
            response = record.get("responseElements")
            if common is None or not isinstance(response, Mapping):
                continue
            account, region, actor, when, app, profile, request = common
            version = _version(request.get("configurationVersion"))
            env = request.get("environmentId")
            if (version is None or not isinstance(env, str) or not _ID.fullmatch(env)
                    or response.get("applicationId") != app
                    or response.get("configurationProfileId") != profile
                    or response.get("environmentId") != env
                    or _version(response.get("configurationVersion")) != version
                    or response.get("state") not in {"DEPLOYING", "BAKING", "COMPLETE"}):
                continue
            deployments.append((when, account, region, actor, app, profile, env, version,
                                response["state"], record))
        elif name == "GetHostedConfigurationVersion":
            common = _common(record, name, True)
            if common is None:
                continue
            account, region, actor, when, app, profile, request = common
            version = _version(request.get("versionNumber"))
            if version is not None:
                reads.append((when, account, region, actor, app, profile, version, record))

    output = []
    for when, account, region, actor, app, profile, env, version, state, deployment in deployments:
        prior = [c for c in creations if c[1:3] == (account, region)
                 and c[4:7] == (app, profile, version)
                 and c[3] != actor and timedelta(0) <= when-c[0] <= timedelta(hours=24)]
        if prior:
            created = max(prior, key=lambda c: c[0])
            output.append(_canonical(deployment, actor, profile,
                "AppConfigCrossActorHostedVersionDeploymentSubmitted",
                "request.appconfig_cross_actor_hosted_version_deployment_submitted",
                {"hosted_version_create_event_id": created[7]["eventID"],
                 "deployment_start_event_id": deployment["eventID"]}))
        previous = [d for d in deployments if d[1:3] == (account, region)
                    and d[4:7] == (app, profile, env) and d[7] > version
                    and d[8] == "COMPLETE" and timedelta(0) < when-d[0] <= timedelta(days=30)]
        if previous:
            newer = max(previous, key=lambda d: d[0])
            output.append(_canonical(deployment, actor, profile,
                "AppConfigHostedVersionRollbackSubmitted",
                "request.appconfig_hosted_version_rollback_submitted",
                {"prior_newer_deployment_event_id": newer[9]["eventID"],
                 "rollback_deployment_event_id": deployment["eventID"]}))
    for when, account, region, actor, app, profile, version, read in reads:
        newer = [d for d in deployments if d[1:3] == (account, region)
                 and d[4:6] == (app, profile) and d[7] > version
                 and d[8] == "COMPLETE" and d[3] != actor
                 and timedelta(0) <= when-d[0] <= timedelta(hours=24)]
        if newer:
            deployment = max(newer, key=lambda d: d[0])
            output.append(_canonical(read, actor, profile,
                "AppConfigPriorHostedVersionReadAfterNewDeployment",
                "request.appconfig_prior_hosted_version_read_after_new_deployment",
                {"newer_deployment_event_id": deployment[9]["eventID"],
                 "hosted_version_read_event_id": read["eventID"]}))
    used_sessions = set()
    for when, account, region, actor, arn, retrieval in sorted(data_retrievals, key=lambda x: x[0]):
        candidates = [s for s in data_sessions if s[1:5] == (account, region, actor, arn)
                      and s[5]["eventID"] not in used_sessions
                      and timedelta(0) <= when-s[0] <= timedelta(minutes=5)]
        if not candidates:
            continue
        session = max(candidates, key=lambda s: s[0])
        used_sessions.add(session[5]["eventID"])
        output.append(_canonical(retrieval, actor, arn,
            "AppConfigConfigurationSessionRetrieved",
            "request.appconfig_data_session_configuration_retrieved",
            {"session_start_event_id": session[5]["eventID"],
             "configuration_get_event_id": retrieval["eventID"]}))
    return output
