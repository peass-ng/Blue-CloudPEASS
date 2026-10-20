"""Private/public ECR push and public repository control signals.

Raw image manifests, authorization tokens and policy documents never enter
normalized detection evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import json
import re
from typing import Any


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPO = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*\Z")
_PUBLIC = "ecr-public.amazonaws.com"
_PRIVATE = "ecr.amazonaws.com"


def _base(record: Mapping[str, Any]) -> tuple[str, str, str, str] | None:
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity = record.get("userIdentity")
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
    return account, region, identity["arn"], record["eventTime"]


def _policy_grants_upload(value: Any, account: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        policy = json.loads(value)
    except (TypeError, ValueError):
        return False
    statements = policy.get("Statement") if isinstance(policy, Mapping) else None
    if not isinstance(statements, list):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        aws = principal.get("AWS") if isinstance(principal, Mapping) else None
        principals = [aws] if isinstance(aws, str) else aws if isinstance(aws, list) else []
        if not any(isinstance(p, str) and p.startswith(f"arn:aws:iam::{account}:role/")
                   for p in principals):
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if isinstance(actions, list) and "ecr-public:PutImage" in actions:
            return True
    return False


def normalize_public(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != _PUBLIC:
        return None
    name = record.get("eventName")
    if not isinstance(name, str) or name not in {"GetAuthorizationToken", "SetRepositoryPolicy", "BatchDeleteImage", "DeleteRepository"}:
        return None
    common = _base(record)
    if common is None or record.get("readOnly") is not (name == "GetAuthorizationToken"):
        return None
    account, _region, actor, when = common
    request = record.get("requestParameters")
    response = record.get("responseElements")
    request = request if isinstance(request, Mapping) else {}
    response = response if isinstance(response, Mapping) else {}
    repo = request.get("repositoryName")
    if name == "GetAuthorizationToken":
        if request:
            return None
        flag, target = "request.ecr_public_authorization_token_requested", None
    elif not isinstance(repo, str) or not _REPO.fullmatch(repo):
        return None
    elif name == "SetRepositoryPolicy":
        if (response.get("registryId") != account or response.get("repositoryName") != repo
                or not _policy_grants_upload(request.get("policyText"), account)
                or not _policy_grants_upload(response.get("policyText"), account)):
            return None
        flag, target = "request.ecr_public_specific_image_publisher_granted", repo
    elif name == "BatchDeleteImage":
        ids, deleted = request.get("imageIds"), response.get("imageIds")
        if (not isinstance(ids, list) or not isinstance(deleted, list)
                or response.get("failures")
                or not any(isinstance(x, Mapping) and isinstance(x.get("imageTag"), str)
                           and any(isinstance(y, Mapping) and y.get("imageTag") == x["imageTag"]
                                   for y in deleted) for x in ids)):
            return None
        flag, target = "request.ecr_public_image_tag_deleted", repo
    else:
        result = response.get("repository")
        if (not isinstance(result, Mapping) or result.get("registryId") != account
                or result.get("repositoryName") != repo):
            return None
        flag, target = "request.ecr_public_repository_deleted", repo
    return {"cloud.provider": "aws", "event.source": _PUBLIC, "event.name": name,
            "event.outcome": "success", "event.id": record["eventID"], "event.time": when,
            "account.id": account, "actor.id": actor, "target.id": target, flag: True}


def _event_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def correlate_new_layer_push(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    uploads: dict[tuple[str, str, str, str, str, str], datetime] = {}
    found: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda x: str(x.get("eventTime", ""))):
        source, name = record.get("eventSource"), record.get("eventName")
        if (not isinstance(source, str) or source not in {_PUBLIC, _PRIVATE}
                or not isinstance(name, str) or name not in {"CompleteLayerUpload", "PutImage"}):
            continue
        common = _base(record)
        if common is None or record.get("readOnly") is not False:
            continue
        account, region, actor, time = common
        when = _event_time(time)
        request, response = record.get("requestParameters"), record.get("responseElements")
        if when is None or not isinstance(request, Mapping) or not isinstance(response, Mapping):
            continue
        repo = request.get("repositoryName")
        if not isinstance(repo, str) or not _REPO.fullmatch(repo):
            continue
        prefix = (source, account, region, actor, repo)
        if name == "CompleteLayerUpload":
            digests = request.get("layerDigests")
            digest = response.get("layerDigest")
            if (response.get("registryId") == account and response.get("repositoryName") == repo
                    and isinstance(digests, list) and digest in digests
                    and isinstance(digest, str) and _DIGEST.fullmatch(digest)):
                uploads[(*prefix, digest)] = when
            continue
        manifest_text, tag = request.get("imageManifest"), request.get("imageTag")
        result = response.get("image")
        image_id = result.get("imageId") if isinstance(result, Mapping) else None
        image_digest = image_id.get("imageDigest") if isinstance(image_id, Mapping) else None
        if (not isinstance(manifest_text, str) or not isinstance(tag, str) or not tag
                or len(tag) > 128 or not isinstance(result, Mapping)
                or result.get("repositoryName") != repo or result.get("registryId") != account
                or not isinstance(image_digest, str) or not _DIGEST.fullmatch(image_digest)):
            continue
        try:
            manifest = json.loads(manifest_text)
        except ValueError:
            continue
        layers = manifest.get("layers") if isinstance(manifest, Mapping) else None
        if not isinstance(layers, list):
            continue
        if not any(isinstance(layer, Mapping) and isinstance(layer.get("digest"), str)
                   and _DIGEST.fullmatch(layer["digest"])
                   and (prior := uploads.get((*prefix, layer["digest"]))) is not None
                   and timedelta(0) <= when - prior <= timedelta(hours=1) for layer in layers):
            continue
        found.append({"cloud.provider": "aws", "event.source": source,
                      "event.name": "PutImage", "event.outcome": "success",
                      "event.id": record["eventID"], "event.time": time,
                      "account.id": account, "actor.id": actor, "target.id": repo + ":" + tag,
                      "request.ecr_public_new_layer_image_pushed" if source == _PUBLIC
                      else "request.ecr_private_new_layer_image_pushed": True})
    return found
