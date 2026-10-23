"""Correlate a private ECR tag move with an auto-deploying App Runner service.

The service configuration must be present in the same bounded input window;
CloudTrail does not reliably emit a separate automatic StartDeployment event.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_REPO = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*\Z")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _envelope(record: Mapping[str, Any]) -> tuple[str, str, datetime, str] | None:
    account, region, stamp, event_id = (record.get(k) for k in
                                        ("recipientAccountId", "awsRegion", "eventTime", "eventID"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(stamp, str)
            or not isinstance(event_id, str) or not event_id
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except ValueError:
        return None
    identity = _map(record.get("userIdentity"))
    if identity.get("accountId") != account or identity.get("type") == "AWSService":
        return None
    return account, region, when, event_id


def _service(record: Mapping[str, Any], account: str, region: str) -> tuple[str, str, str] | None:
    name = record.get("eventName")
    request = _map(record.get("requestParameters"))
    service = _map(_map(record.get("responseElements")).get("service"))
    arn = service.get("serviceArn")
    prefix = f"arn:aws:apprunner:{region}:{account}:service/"
    if (name not in {"CreateService", "UpdateService"}
            or not isinstance(arn, str) or not arn.startswith(prefix)
            or len(arn) <= len(prefix)
            or (name == "CreateService" and request.get("serviceName") != service.get("serviceName"))
            or (name == "UpdateService" and request.get("serviceArn") != arn)):
        return None
    source = _map(request.get("sourceConfiguration"))
    returned = _map(service.get("sourceConfiguration"))
    image = _map(source.get("imageRepository"))
    confirmed = _map(returned.get("imageRepository"))
    if (source.get("autoDeploymentsEnabled") is not True
            or returned.get("autoDeploymentsEnabled") is not True
            or image.get("imageRepositoryType") != "ECR"
            or confirmed.get("imageRepositoryType") != "ECR"
            or image.get("imageIdentifier") != confirmed.get("imageIdentifier")):
        return None
    identifier = image.get("imageIdentifier")
    registry = f"{account}.dkr.ecr.{region}.amazonaws.com/"
    if not isinstance(identifier, str) or not identifier.startswith(registry):
        return None
    path = identifier[len(registry):]
    if ":" not in path or "@" in path:
        return None
    repo, tag = path.rsplit(":", 1)
    if not _REPO.fullmatch(repo) or not _TAG.fullmatch(tag):
        return None
    return arn, repo, tag


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Require an observed auto-deploy service and a changed tagged digest."""
    active: dict[str, tuple[str, str, str, str]] = {}
    seen: dict[tuple[str, str, str, str], tuple[datetime, str]] = {}
    findings: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda x: str(x.get("eventTime", ""))):
        if not isinstance(record, Mapping):
            continue
        envelope = _envelope(record)
        if envelope is None:
            continue
        account, region, when, event_id = envelope
        source, name = record.get("eventSource"), record.get("eventName")
        if source == "apprunner.amazonaws.com":
            if name in {"CreateService", "UpdateService"}:
                config = _service(record, account, region)
                if config is not None:
                    arn, repo, tag = config
                    active[arn] = account, region, repo, tag
                elif name == "UpdateService":
                    request = _map(record.get("requestParameters"))
                    target = request.get("serviceArn")
                    if "sourceConfiguration" in request and isinstance(target, str):
                        active.pop(target, None)
            elif name == "DeleteService":
                target = _map(record.get("requestParameters")).get("serviceArn")
                if isinstance(target, str):
                    active.pop(target, None)
            continue
        if source != "ecr.amazonaws.com" or name != "PutImage":
            continue
        request = _map(record.get("requestParameters"))
        image = _map(_map(record.get("responseElements")).get("image"))
        image_id = _map(image.get("imageId"))
        repo, tag, digest = request.get("repositoryName"), request.get("imageTag"), image_id.get("imageDigest")
        if (not isinstance(repo, str) or not _REPO.fullmatch(repo)
                or not isinstance(tag, str) or not _TAG.fullmatch(tag)
                or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
                or request.get("registryId") != account
                or image.get("registryId") != account
                or image.get("repositoryName") != repo
                or image_id.get("imageTag") != tag):
            continue
        key = account, region, repo, tag
        prior = seen.get(key)
        if prior is not None and prior[1] != digest and timedelta(0) <= when - prior[0] <= timedelta(days=7):
            identity = _map(record.get("userIdentity"))
            for arn, target in active.items():
                if target != key:
                    continue
                findings.append({
                    "cloud.provider": "aws", "event.source": "ecr.amazonaws.com",
                    "event.name": "PutImage", "event.outcome": "success",
                    "event.id": event_id, "event.time": record["eventTime"],
                    "account.id": account, "actor.id": identity.get("arn"),
                    "target.id": "sha256:" + hashlib.sha256(arn.encode()).hexdigest()[:24],
                    "request.apprunner_auto_deploy_tag_repointed": True,
                })
        seen[key] = when, digest
    return findings
