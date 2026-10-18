"""Signed S3 cross-Region replication predicate over cached bucket facts only."""
from __future__ import annotations

import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects
from .fixtures import CASES


CHECK_ID = "aws_nist_s3_bucket_cross_region_replication_enabled"
_BUCKET_ARN = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):s3:::([^:/]+)$")
_CALLER_ARN = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):[^:]+:[^:]*:([0-9]{12}):.+$")
_GLOBAL_SCOPE = re.compile(r"^([0-9]{12})/global$")


def _authority(index, source):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS scope authority unavailable")
    scope = get(context, "scope", str)
    match = _GLOBAL_SCOPE.fullmatch(scope)
    if match is None:
        raise Unavailable("bucket inventory is not account-global scoped")
    account = match.group(1)
    if get(context, "Account", str) != account:
        raise Unavailable("audited account differs from bucket scope")
    if get(source, "AccountId", str) != account:
        raise Unavailable("source bucket account differs from audited account")
    metadata = get(context, "metadata", dict)
    callers = get(metadata, "caller_identities", list)
    partitions = set()
    for caller in callers:
        if not isinstance(caller, dict):
            raise Unavailable("malformed caller identity")
        if caller.get("Account") != account:
            continue
        arn = get(caller, "Arn", str)
        arn_match = _CALLER_ARN.fullmatch(arn)
        if arn_match is None or arn_match.group(2) != account:
            raise Unavailable("caller ARN does not prove audited partition and account")
        partitions.add(arn_match.group(1))
    if len(partitions) != 1:
        raise Unavailable("audited cloud partition unavailable or ambiguous")
    envelopes = get(index, "collections", dict).get("bucket")
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("bucket inventory envelope unavailable or ambiguous")
    envelope = envelopes[0]
    if not isinstance(envelope, dict) or envelope.get("type") != "bucket" or envelope.get("scope") != scope or envelope.get("account_id") != account or envelope.get("global") is not True:
        raise Unavailable("bucket inventory envelope does not prove account-global scope")
    return account, partitions.pop()


def _region(bucket):
    location = get(bucket, "Location", dict)
    if "LocationConstraint" not in location:
        raise Unavailable("bucket location unavailable")
    value = location["LocationConstraint"]
    if value in (None, ""):
        return "us-east-1"
    if not isinstance(value, str):
        raise Unavailable("malformed bucket location")
    return "eu-west-1" if value == "EU" else value


def _replication_rules(bucket):
    detail = get(bucket, "Replication", dict)
    if detail.get("collection_status") == "empty":
        if detail.get("absent") is not True:
            raise Unavailable("unproven absent replication configuration")
        return []
    return list_of_objects(get(detail, "ReplicationConfiguration.Rules", list))


@register(CHECK_ID, "aws", "hardening", "bucket",
          "S3 bucket has enabled replication to a bucket in another Region",
          "medium", "CP-9",
          "Configure a reviewed cross-Region replication rule and verify its destination Region.",
          dependencies=["bucket"])
def cross_region_replication(bucket, index):
    source_name = get(bucket, "Name", str)
    account, partition = _authority(index, bucket)
    destinations = {}
    for candidate in complete_items(index, "bucket"):
        if get(candidate, "AccountId", str) != account:
            raise Unavailable("bucket inventory contains a foreign-account item")
        name = get(candidate, "Name", str)
        if name in destinations:
            raise Unavailable("duplicate bucket identity in scoped inventory")
        destinations[name] = candidate
    if source_name not in destinations:
        raise Unavailable("source bucket absent from scoped inventory")
    if destinations[source_name] != bucket:
        raise Unavailable("source bucket differs from scoped inventory fact")
    rules = _replication_rules(bucket)
    enabled = []
    uncertain = False
    for rule in rules:
        status = get(rule, "Status", str)
        if status == "Enabled":
            enabled.append(rule)
        elif status != "Disabled":
            uncertain = True
    if not enabled:
        if uncertain:
            return unknown("unrecognized replication-rule status", source_bucket=source_name)
        return result(True, source_bucket=source_name, enabled_rules=0,
                      semantics="No enabled replication rule is declared")

    source_region = _region(bucket)
    # The existing S3 collector lists owned buckets once and obtains each
    # bucket's Location. An external destination is not resolved by that
    # inventory, so its Region must never be inferred from the ARN or name.
    same_region = 0
    for rule in enabled:
        destination = get(rule, "Destination.Bucket", str)
        match = _BUCKET_ARN.fullmatch(destination)
        if not match or match.group(1) != partition:
            uncertain = True
            continue
        destination_bucket = destinations.get(match.group(2))
        if destination_bucket is None:
            uncertain = True
            continue
        try:
            destination_region = _region(destination_bucket)
        except Unavailable:
            uncertain = True
            continue
        if destination_region != source_region:
            return result(False, source_bucket=source_name, source_region=source_region,
                          destination_bucket=match.group(2), destination_region=destination_region,
                          semantics="An enabled rule names a collected bucket in a different Region")
        same_region += 1
    if uncertain:
        return unknown("enabled replication destination Region cannot be resolved",
                       source_bucket=source_name, source_region=source_region,
                       enabled_rules=len(enabled), same_region_rules=same_region)
    return result(True, source_bucket=source_name, source_region=source_region,
                  enabled_rules=len(enabled), same_region_rules=same_region,
                  semantics="All enabled replication destinations are in the source Region")


def _bucket(name, region=None, destination=None):
    replication = {"collection_status": "empty", "absent": True}
    if destination is not None:
        replication = {"collection_status": "collected", "ReplicationConfiguration": {
            "Rules": [{"Status": "Enabled", "Destination": {
                "Bucket": "arn:aws:s3:::" + destination}}]}}
    return {"Name": name, "AccountId": "111111111111",
        "Location": {"collection_status": "collected", "LocationConstraint": region},
        "Replication": replication}


def _bucket_index(*buckets):
    scope = "111111111111/global"
    return {"context": {"provider": "aws", "scope": scope, "Account": "111111111111",
        "metadata": {"caller_identities": [{"Account": "111111111111",
            "Arn": "arn:aws:sts::111111111111:assumed-role/audit/session"}]}},
        "collections": {"bucket": [{"type": "bucket", "scope": scope,
            "account_id": "111111111111", "global": True, "status": "collected",
            "items": list(buckets)}]},
        "bucket": [{"type": "bucket", "scope": scope, "data": row}
            for row in buckets]}


_source = _bucket("source-example", None, "destination-example")
_destination = _bucket("destination-example", "eu-west-1")
_unreplicated = _bucket("source-example")
_unresolved = _bucket("source-example", None, "uncollected-destination")
CASES[CHECK_ID] = {"pass": _source,
    "pass_index": _bucket_index(_source, _destination),
    "fail": _unreplicated, "fail_index": _bucket_index(_unreplicated),
    "unknown": _unresolved, "unknown_index": _bucket_index(_unresolved),
    "index": _bucket_index(_source, _destination)}
