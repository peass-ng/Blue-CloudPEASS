"""Normalize CodeArtifact npm registry CloudTrail events observed in a disposable lab."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_DOMAIN = re.compile(r"[a-z][a-z0-9-]{1,49}\Z")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,99}\Z")
_PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,213}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_EVENTS = {"PublishPackageVersion", "PutPackageMetadata", "ReadFromRepository"}


def normalize_aws_codeartifact_npm(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "codeartifact.amazonaws.com" or name not in _EVENTS
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "ReadFromRepository")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)
            or request.get("domainOwner") != account
            or request.get("packageFormat") != "npm"):
        return None
    domain, repo, package = (request.get(k) for k in
                             ("domainName", "repositoryName", "packageName"))
    if (not isinstance(domain, str) or not _DOMAIN.fullmatch(domain)
            or not isinstance(repo, str) or not _REPO.fullmatch(repo)
            or not isinstance(package, str) or not _PACKAGE.fullmatch(package)):
        return None
    if name != "ReadFromRepository":
        version = request.get("packageVersion")
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": record["eventSource"],
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor.get("arn"),
        "target.id": f"arn:aws:codeartifact:{region}:{account}:repository/{domain}/{repo}",
        "request.codeartifact_npm_published": name == "PublishPackageVersion" and not failed,
        "request.codeartifact_npm_metadata_updated": name == "PutPackageMetadata" and not failed,
        "request.codeartifact_npm_repository_read": name == "ReadFromRepository" and not failed,
    }
