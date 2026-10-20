"""Private ECR pull, policy and deletion signals plus Lightsail ECR role activation.

Tokens, signed URLs, image manifests and policy bodies are never copied into
canonical detection evidence.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import json
import re
from typing import Any


_REPO = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SERVICE = re.compile(r"[a-z0-9][a-z0-9-]{1,62}\Z")
_FLAGS = {
    "GetAuthorizationToken": "request.ecr_authorization_token_requested",
    "BatchGetImage": "request.ecr_image_manifest_requested",
    "GetDownloadUrlForLayer": "request.ecr_layer_download_url_requested",
    "SetRepositoryPolicy": "request.ecr_specific_image_reader_granted",
    "BatchDeleteImage": "request.ecr_image_tag_deleted",
    "UpdateContainerService": "request.lightsail_ecr_image_puller_role_activated",
}


def _common(record: Mapping[str, Any]) -> tuple[str, str, str] | None:
    account = record.get("recipientAccountId")
    identity = record.get("userIdentity")
    region = record.get("awsRegion")
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str) or not record["eventTime"]
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    return account, region, identity["arn"]


def _reader_grant(value: Any) -> bool:
    if not isinstance(value, str): return False
    try:
        policy = json.loads(value)
    except (ValueError, TypeError):
        return False
    statements = policy.get("Statement") if isinstance(policy, Mapping) else None
    if not isinstance(statements, list): return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow": continue
        principal = statement.get("Principal")
        if not isinstance(principal, Mapping): continue
        aws = principal.get("AWS")
        principals = [aws] if isinstance(aws, str) else aws if isinstance(aws, list) else []
        if not principals or not all(isinstance(x, str) and x.startswith("arn:aws:iam::")
                                     and ":role/" in x for x in principals):
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if isinstance(actions, list) and "ecr:BatchGetImage" in actions:
            return True
    return False


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name, source = record.get("eventName"), record.get("eventSource")
    if name not in _FLAGS or source != ("lightsail.amazonaws.com" if name == "UpdateContainerService"
                                      else "ecr.amazonaws.com"):
        return None
    common = _common(record)
    if common is None or record.get("readOnly") is not (name in {
            "GetAuthorizationToken", "BatchGetImage", "GetDownloadUrlForLayer"}):
        return None
    account, region, actor = common
    request = record.get("requestParameters")
    response = record.get("responseElements")
    request = request if isinstance(request, Mapping) else {}
    response = response if isinstance(response, Mapping) else {}
    target = None
    accepted = False
    if name == "GetAuthorizationToken":
        accepted = not request
    elif name in {"BatchGetImage", "GetDownloadUrlForLayer"}:
        target = request.get("repositoryName")
        accepted = isinstance(target, str) and bool(_REPO.fullmatch(target))
        if name == "BatchGetImage":
            ids = request.get("imageIds")
            accepted = (accepted and isinstance(ids, list) and bool(ids)
                        and all(isinstance(x, Mapping) and
                                (isinstance(x.get("imageTag"), str) or
                                 isinstance(x.get("imageDigest"), str)) for x in ids))
        else:
            accepted = accepted and isinstance(request.get("layerDigest"), str) and bool(
                _DIGEST.fullmatch(request["layerDigest"]))
    elif name == "SetRepositoryPolicy":
        target = request.get("repositoryName")
        accepted = (isinstance(target, str) and bool(_REPO.fullmatch(target))
                    and response.get("repositoryName") == target
                    and response.get("registryId") == account
                    and _reader_grant(request.get("policyText"))
                    and _reader_grant(response.get("policyText")))
    elif name == "BatchDeleteImage":
        target = request.get("repositoryName")
        ids, deleted = request.get("imageIds"), response.get("imageIds")
        accepted = (isinstance(target, str) and bool(_REPO.fullmatch(target))
                    and isinstance(ids, list) and isinstance(deleted, list)
                    and any(isinstance(x, Mapping) and isinstance(x.get("imageTag"), str)
                            and any(isinstance(y, Mapping) and y.get("imageTag") == x["imageTag"]
                                    for y in deleted) for x in ids)
                    and not response.get("failures"))
    else:
        target = request.get("serviceName")
        role = request.get("privateRegistryAccess")
        result = response.get("containerService")
        accepted = (isinstance(target, str) and bool(_SERVICE.fullmatch(target))
                    and isinstance(role, Mapping)
                    and isinstance(role.get("ecrImagePullerRole"), Mapping)
                    and role["ecrImagePullerRole"].get("isActive") is True
                    and isinstance(result, Mapping)
                    and result.get("containerServiceName") == target
                    and isinstance(result.get("privateRegistryAccess"), Mapping)
                    and isinstance(result["privateRegistryAccess"].get("ecrImagePullerRole"), Mapping)
                    and result["privateRegistryAccess"]["ecrImagePullerRole"].get("isActive") is True)
    if not accepted: return None
    return {"cloud.provider": "aws", "event.source": source,
            "event.name": name, "event.outcome": "success", "event.id": record["eventID"],
            "event.time": record["eventTime"], "account.id": account,
            "actor.id": actor, "target.id": target, _FLAGS[name]: True}


def correlate_tag_overwrite(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str, str, str], tuple[datetime, str]] = {}
    out: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda x: str(x.get("eventTime", ""))):
        if (record.get("eventSource") != "ecr.amazonaws.com"
                or record.get("eventName") != "PutImage" or record.get("readOnly") is not False):
            continue
        common = _common(record)
        if common is None: continue
        account, region, actor = common
        request = record.get("requestParameters")
        response = record.get("responseElements")
        if not isinstance(request, Mapping) or not isinstance(response, Mapping): continue
        repo, tag = request.get("repositoryName"), request.get("imageTag")
        image = response.get("image")
        if not isinstance(image, Mapping): continue
        image_id = image.get("imageId")
        digest = image_id.get("imageDigest") if isinstance(image_id, Mapping) else None
        if (not isinstance(repo, str) or not _REPO.fullmatch(repo)
                or not isinstance(tag, str) or not tag or len(tag) > 128
                or image.get("repositoryName") != repo
                or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)):
            continue
        try:
            when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        except ValueError:
            continue
        key = account, region, repo, tag
        prior = seen.get(key)
        if prior is not None and prior[1] != digest and timedelta(0) <= when-prior[0] <= timedelta(days=7):
            out.append({"cloud.provider": "aws", "event.source": "ecr.amazonaws.com",
                        "event.name": "PutImage", "event.outcome": "success",
                        "event.id": record["eventID"], "event.time": record["eventTime"],
                        "account.id": account, "actor.id": actor, "target.id": repo + ":" + tag,
                        "request.ecr_image_tag_digest_changed": True})
        seen[key] = when, digest
    return out
