"""Exact reviewed S3 bucket-policy self-grants.

PutBucketPolicy can add a bucket resource-policy Allow for the caller, but a
write alone does not prove an effective new permission. This contract requires
the exact principal, bucket, object prefix and before/after authorization result.
"""
from __future__ import annotations

import re

from . import Node, inventory_status, items

COLLECTION = "aws_s3_policy_self_grant_evidence"
TECHNIQUE = "aws-s3-putbucketpolicy-self-grant"
_SOURCE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):iam::(\d{12}):(user|role)/[^*?\s]+")
_BUCKET = re.compile(r"arn:(aws|aws-cn|aws-us-gov):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")


def valid(record, account):
    if not isinstance(record, dict) or not isinstance(account, str):
        return False
    source = record.get("SourceArn")
    bucket = record.get("BucketArn")
    match = _SOURCE.fullmatch(source) if isinstance(source, str) else None
    if not match or match.group(2) != account or not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket):
        return False
    prefix = record.get("ObjectPrefix")
    if not isinstance(prefix, str) or not prefix or "*" in prefix or ".." in prefix or prefix.startswith("/"):
        return False
    expected = {
        "TechniqueId": TECHNIQUE,
        "Status": "verified",
        "BucketOwnerAccount": account,
        "PolicyPrincipalArn": source,
        "GrantedAction": "s3:GetObject",
        "PolicyResourceArn": f"{bucket}/{prefix}*",
        "PriorAccessDenied": True,
        "PolicyAccepted": True,
        "EffectiveAccessAfterAllowed": True,
        "GuardrailsReviewed": True,
    }
    if any(type(record.get(key)) is not type(value) or record[key] != value for key, value in expected.items()):
        return False
    return isinstance(record.get("EvidenceRef"), str) and bool(record["EvidenceRef"].strip())


def load(model):
    status = inventory_status(model.snapshot, COLLECTION)
    records = {}
    for scope, record in items(model.snapshot, COLLECTION):
        account = scope.split("/")[0]
        if status.get(scope) not in ("collected", "empty") or not valid(record, account):
            continue
        bucket, source, prefix = record["BucketArn"], record["SourceArn"], record["ObjectPrefix"]
        target_id = f"aws_verified_authority:s3-policy:{bucket}/{prefix}:{source}"
        records.setdefault(target_id, []).append((account, record))
    nodes, unique = {}, {}
    for target_id, matches in records.items():
        if len(matches) != 1:
            continue
        account, record = matches[0]
        bucket, prefix = record["BucketArn"], record["ObjectPrefix"]
        nodes[target_id] = Node(target_id, "aws_verified_authority", "aws", account,
                                f"s3:GetObject on {bucket}/{prefix}*",
                                attrs={"account": account, "arn": bucket, "resource_arn": bucket,
                                       "source_id": record["SourceArn"], "object_prefix": prefix}, entity=True)
        unique[target_id] = record
    return nodes, unique
