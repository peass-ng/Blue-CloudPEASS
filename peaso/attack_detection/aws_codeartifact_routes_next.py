"""Normalize verified CodeArtifact token, package publish and asset-read calls."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,99}\Z")
_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_SHA = re.compile(r"[a-fA-F0-9]{64}\Z")


def normalize_aws_codeartifact_routes(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "codeartifact.amazonaws.com"
            or name not in {"GetAuthorizationToken", "PublishPackageVersion", "GetPackageVersionAsset"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name != "PublishPackageVersion")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)
            or response is not None and not isinstance(response, Mapping)):
        return None
    domain = request.get("domain")
    if not isinstance(domain, str) or not _NAME.fullmatch(domain):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    token_request = name == "GetAuthorizationToken" and not failed
    published = read_asset = False
    target = f"arn:aws:codeartifact:{region}:{account}:domain/{domain}"
    if name != "GetAuthorizationToken":
        repo, fmt, namespace, package, version = (
            request.get(k) for k in ("repository", "format", "namespace", "packageName", "packageVersion"))
        if (not isinstance(repo, str) or not _NAME.fullmatch(repo)
                or fmt != "generic" or not isinstance(namespace, str)
                or not _PART.fullmatch(namespace) or not isinstance(package, str)
                or not _PART.fullmatch(package) or not isinstance(version, str)
                or not _VERSION.fullmatch(version)):
            return None
        target = f"arn:aws:codeartifact:{region}:{account}:package/{domain}/{repo}/{fmt}/{namespace}/{package}"
        if name == "PublishPackageVersion":
            asset, digest = request.get("assetName"), request.get("assetSHA256")
            published = bool(not failed and isinstance(asset, str) and _PART.fullmatch(asset)
                             and isinstance(digest, str) and _SHA.fullmatch(digest)
                             and isinstance(response, Mapping)
                             and response.get("format") == fmt
                             and response.get("namespace") == namespace
                             and response.get("packageName") == package
                             and response.get("version") == version
                             and response.get("status") == "Published")
        else:
            asset = request.get("asset")
            read_asset = bool(not failed and isinstance(asset, str) and _PART.fullmatch(asset))
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": record["eventSource"],
            "event.name": name, "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
            "request.codeartifact_token_requested": token_request,
            "request.codeartifact_generic_version_published": published,
            "request.codeartifact_generic_asset_read": read_asset}
