"""Bounded CloudTrail signals for EKS access and endpoint changes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any
from urllib.parse import unquote


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_CLUSTER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}\Z")
_IAM_PRINCIPAL = re.compile(r"arn:aws(?:-[a-z-]+)?:iam::[0-9]{12}:(?:role|user)/[^\s]{1,512}\Z")
_ROLE = re.compile(r"arn:aws(?:-[a-z-]+)?:iam::[0-9]{12}:role/[^\s]{1,512}\Z")
_ADMIN_POLICY = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
_NAMES = {
    "CreateAccessEntry", "UpdateAccessEntry", "AssociateAccessPolicy",
    "CreatePodIdentityAssociation", "UpdatePodIdentityAssociation",
    "UpdateClusterConfig",
}


def _valid_text(value: Any, *, maximum: int = 512) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and not any(c.isspace() for c in value)


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Emit action flags and hashes only; request values never reach findings."""
    name = record.get("eventName")
    if (record.get("eventSource") != "eks.amazonaws.com" or name not in _NAMES
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return []
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    event_id, stamp = record.get("eventID"), record.get("eventTime")
    request, response = record.get("requestParameters"), record.get("responseElements")
    resources = record.get("resources")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not _valid_text(event_id, maximum=128)
            or not isinstance(stamp, str)
            or not isinstance(request, Mapping)
            or response is not None and not isinstance(response, Mapping)
            or resources is not None and (not isinstance(resources, list) or len(resources) > 100)):
        return []
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return []
    except ValueError:
        return []
    identity = record.get("userIdentity")
    if (not isinstance(identity, Mapping) or identity.get("invokedBy")
            or identity.get("type") == "AWSService"):
        return []
    cluster = request.get("name", request.get("clusterName"))
    if not isinstance(cluster, str) or not _CLUSTER.fullmatch(cluster):
        return []
    flags: dict[str, bool] = {}
    target_suffix = cluster
    if name in {"CreateAccessEntry", "UpdateAccessEntry", "AssociateAccessPolicy"}:
        raw_principal = request.get("principalArn")
        if not _valid_text(raw_principal, maximum=1024):
            return []
        principal = unquote(raw_principal)
        if not _IAM_PRINCIPAL.fullmatch(principal):
            return []
        target_suffix = f"{cluster}:{principal}"
        if name == "CreateAccessEntry":
            flags["request.eks_access_entry_created"] = True
        if name in {"CreateAccessEntry", "UpdateAccessEntry"}:
            groups = request.get("kubernetesGroups")
            if groups is not None:
                if (not isinstance(groups, list) or not groups or len(groups) > 50
                        or any(not _valid_text(group, maximum=128) for group in groups)):
                    return []
                flags["request.eks_access_groups_configured"] = True
        if name == "AssociateAccessPolicy":
            scope = request.get("accessScope")
            if (request.get("policyArn") == _ADMIN_POLICY
                    and isinstance(scope, Mapping) and scope.get("type") == "cluster"):
                flags["request.eks_cluster_admin_policy_granted"] = True
    elif name == "CreatePodIdentityAssociation":
        role = request.get("roleArn")
        namespace, service_account = request.get("namespace"), request.get("serviceAccount")
        if (not isinstance(role, str) or not _ROLE.fullmatch(role)
                or not _valid_text(namespace, maximum=63)
                or not _valid_text(service_account, maximum=253)):
            return []
        target_suffix = f"{cluster}:{namespace}:{service_account}"
        flags["request.eks_pod_identity_role_bound"] = True
    elif name == "UpdatePodIdentityAssociation":
        association = request.get("associationId")
        if not _valid_text(association, maximum=128):
            return []
        target_suffix = f"{cluster}:{association}"
        if any(isinstance(request.get(field), str) and _ROLE.fullmatch(request[field])
               for field in ("roleArn", "targetRoleArn")) or request.get("disableSessionTags") is True:
            flags["request.eks_pod_identity_association_repointed"] = True
    elif name == "UpdateClusterConfig":
        vpc = request.get("resourcesVpcConfig")
        cidrs = vpc.get("publicAccessCidrs") if isinstance(vpc, Mapping) else None
        if (isinstance(vpc, Mapping) and vpc.get("endpointPublicAccess") is True
                and isinstance(cidrs, list) and len(cidrs) <= 100
                and ("0.0.0.0/0" in cidrs or "::/0" in cidrs)):
            flags["request.eks_public_api_exposed"] = True
    if not flags:
        return []
    actor = identity.get("arn")
    target = "sha256:" + hashlib.sha256(
        f"{account}:{region}:{target_suffix}".encode("utf-8")
    ).hexdigest()[:24]
    return [{
        "cloud.provider": "aws", "event.source": "eks.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": event_id, "event.time": stamp,
        "account.id": account, "actor.id": actor,
        "target.id": target, **flags,
    }]
