"""Reviewed AWS self permission gains on an exact service resource.

Each contract fixes the source action and gained permission. A service write or
an unreviewed claim cannot manufacture an authority node.
"""
from __future__ import annotations

import re

from . import Node, inventory_status, items

SOURCE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):iam::(\d{12}):(user|role)/[^*?\s]+")
REGIONAL = re.compile(r"arn:(aws|aws-cn|aws-us-gov):([a-z0-9-]+):([a-z0-9-]+):(\d{12}):(.+)")

# Selector -> collection, catalog ID, ARN service/resource prefix, exact gained permission.
CONTRACTS = {
    "aws_secretsmanager_policy_self_grant": (
        "aws_secretsmanager_policy_self_grant_evidence", "aws-secretsmanager-putresourcepolicy-self-grant",
        "secretsmanager", "secret:", "secretsmanager:GetSecretValue"),
    "aws_efs_policy_self_grant": (
        "aws_efs_policy_self_grant_evidence", "aws-efs-putfilesystempolicy-self-grant",
        "elasticfilesystem", "file-system/", "elasticfilesystem:ClientMount"),
    "aws_cases_tag_self_grant": (
        "aws_cases_tag_self_grant_evidence", "aws-cases-tagresource-domain-event-self-grant",
        "cases", "domain/", "cases:PutCaseEventConfiguration"),
    "aws_sitewise_portal_self_grant": (
        "aws_sitewise_portal_self_grant_evidence", "aws-sitewise-createaccesspolicy-portal-self-grant",
        "iotsitewise", "portal/", "iotsitewise:MonitorPortalAdministrator"),
}


def _valid(record, account, region, selector):
    if not isinstance(record, dict):
        return False
    collection, technique, service, prefix, gained = CONTRACTS[selector]
    source, resource = record.get("SourceArn"), record.get("ResourceArn")
    src = SOURCE.fullmatch(source) if isinstance(source, str) else None
    res = REGIONAL.fullmatch(resource) if isinstance(resource, str) else None
    if isinstance(resource, str) and ("*" in resource or "?" in resource or any(c.isspace() for c in resource)):
        return False
    if not src or not res or src.group(2) != account or res.group(4) != account:
        return False
    if src.group(1) != res.group(1) or res.group(2) != service or res.group(3) != region:
        return False
    if not res.group(5).startswith(prefix) or not res.group(5)[len(prefix):]:
        return False
    # A domain grant applies to one domain, not an arbitrary Cases child.
    if selector == "aws_cases_tag_self_grant" and "/" in res.group(5)[len(prefix):]:
        return False
    expected = {
        "TechniqueId": technique,
        "Status": "verified",
        "SourceArn": source,
        "ResourceArn": resource,
        "SourceAccount": account,
        "GrantedPermission": gained,
        "PriorAccessDenied": True,
        "EffectiveAccessAfterAllowed": True,
        "GuardrailsReviewed": True,
    }
    if selector == "aws_secretsmanager_policy_self_grant":
        if src.group(3) != "user":
            return False
        expected.update(PolicyPrincipalArn=source, PolicyResourceArn=resource,
                        PolicyAccepted=True, KmsDecryptAfterAllowed=True)
    elif selector == "aws_efs_policy_self_grant":
        expected.update(PolicyPrincipalArn=source, PolicyResourceArn=resource,
                        PolicyAccepted=True)
    elif selector == "aws_cases_tag_self_grant":
        expected.update(TagKey="Access", TagValue="Operator",
                        IAMConditionKey="aws:ResourceTag/Access", IAMConditionValue="Operator",
                        TagWriteAccepted=True, AllEvaluatedResourcesCovered=True)
    elif selector == "aws_sitewise_portal_self_grant":
        expected.update(TargetIdentityArn=source, AccessPolicyIdentityArn=source,
                        AccessPolicyResourceArn=resource, AccessPolicyPermission="ADMINISTRATOR",
                        AccessPolicyAccepted=True, MonitorAvailable=True)
    if any(type(record.get(k)) is not type(v) or record[k] != v for k, v in expected.items()):
        return False
    return isinstance(record.get("EvidenceRef"), str) and bool(record["EvidenceRef"].strip())


def load(model):
    """Return selector-keyed exact targets and unique reviewed records."""
    result = {}
    for selector, (collection, _, _, _, gained) in CONTRACTS.items():
        status = inventory_status(model.snapshot, collection)
        matches = {}
        for scope, record in items(model.snapshot, collection):
            parts = str(scope).split("/")
            if len(parts) != 2 or status.get(scope) != "collected":
                continue
            account, region = parts
            if not _valid(record, account, region, selector):
                continue
            resource, source = record["ResourceArn"], record["SourceArn"]
            target_id = f"aws_verified_authority:{selector}:{resource}:{source}"
            matches.setdefault(target_id, []).append((account, record))
        nodes, unique = {}, {}
        for target_id, records in matches.items():
            if len(records) != 1:
                continue
            account, record = records[0]
            resource = record["ResourceArn"]
            nodes[target_id] = Node(target_id, "aws_verified_authority", "aws", account,
                                    f"{gained} on {resource}",
                                    attrs={"account": account, "arn": resource,
                                           "resource_arn": resource, "source_id": record["SourceArn"]},
                                    entity=True)
            unique[target_id] = record
        result[selector] = (nodes, unique)
    return result
