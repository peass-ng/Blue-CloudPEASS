"""Reviewed, prefix-bounded S3 Access Grants permission gain.

The vended STS token is scoped to S3 data. It never represents the full
permissions of the location role in the graph.
"""
from __future__ import annotations

import re

from . import Node, inventory_status, items

COLLECTION = "aws_s3_access_grants_self_grant_evidence"
TECHNIQUE = "aws-s3-accessgrants-self-grant"
_SOURCE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):iam::(\d{12}):(user|role)/[^*?\s]+")
_ROLE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):iam::(\d{12}):role/[^*?\s]+")
_INSTANCE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):s3:[a-z0-9-]+:(\d{12}):access-grants/default")
_LOCATION = re.compile(r"arn:(aws|aws-cn|aws-us-gov):s3:[a-z0-9-]+:(\d{12}):access-grants/(?:default/)?location/[A-Za-z0-9-]+")
_BUCKET = re.compile(r"arn:(aws|aws-cn|aws-us-gov):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")


def valid(record, account):
    if not isinstance(record, dict) or not isinstance(account, str):
        return False
    source, role, instance, location, bucket = (record.get(k) for k in
        ("SourceArn", "LocationRoleArn", "AccessGrantsInstanceArn", "LocationArn", "BucketArn"))
    matches = [pattern.fullmatch(value) if isinstance(value, str) else None
               for pattern, value in ((_SOURCE, source), (_ROLE, role), (_INSTANCE, instance),
                                      (_LOCATION, location), (_BUCKET, bucket))]
    if not all(matches) or any(m.group(2) != account for m in matches[:4]):
        return False
    prefix = record.get("ObjectPrefix")
    if not isinstance(prefix, str) or not prefix or "*" in prefix or ".." in prefix or prefix.startswith("/"):
        return False
    expected = {
        "TechniqueId": TECHNIQUE,
        "Status": "verified",
        "GrantGranteeArn": source,
        "GrantPermission": "READ",
        "GrantScope": f"s3://{bucket.rsplit(':', 1)[-1]}/{prefix}*",
        "RoleTrustsAccessGrants": True,
        "LocationRoleAllowsGetObject": True,
        "PriorAccessDenied": True,
        "LocationRegistered": True,
        "GrantCreated": True,
        "GetDataAccessSucceeded": True,
        "SessionSubjectRoleArn": role,
        "SessionScope": f"s3://{bucket.rsplit(':', 1)[-1]}/{prefix}*",
        "CredentialUsable": True,
        "EffectiveAccessAfterAllowed": True,
    }
    if any(type(record.get(key)) is not type(value) or record[key] != value for key, value in expected.items()):
        return False
    grant_arn = record.get("GrantArn")
    if not isinstance(grant_arn, str) or not grant_arn.startswith(instance + "/grant-") or "*" in grant_arn:
        return False
    return isinstance(record.get("EvidenceRef"), str) and bool(record["EvidenceRef"].strip())


def load(model):
    status = inventory_status(model.snapshot, COLLECTION)
    records = {}
    for scope, record in items(model.snapshot, COLLECTION):
        account = scope.split("/")[0]
        if status.get(scope) not in ("collected", "empty") or not valid(record, account):
            continue
        target_id = (f"aws_verified_authority:s3-access-grants:{record['BucketArn']}/{record['ObjectPrefix']}:"
                     f"{record['SourceArn']}")
        records.setdefault(target_id, []).append((account, record))
    nodes, unique = {}, {}
    for target_id, matches in records.items():
        if len(matches) != 1:
            continue
        account, record = matches[0]
        bucket, prefix = record["BucketArn"], record["ObjectPrefix"]
        nodes[target_id] = Node(target_id, "aws_verified_authority", "aws", account,
                                f"S3 Access Grants READ on {bucket}/{prefix}*",
                                attrs={"account": account, "resource_arn": record["AccessGrantsInstanceArn"],
                                       "arn": record["AccessGrantsInstanceArn"], "role_arn": record["LocationRoleArn"],
                                       "location_arn": record["LocationArn"], "source_id": record["SourceArn"],
                                       "bucket_arn": bucket, "object_prefix": prefix}, entity=True)
        unique[target_id] = record
    return nodes, unique
