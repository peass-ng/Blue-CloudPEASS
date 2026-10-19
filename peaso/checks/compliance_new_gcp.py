"""Defensive GCP predicates for individually reviewed signed compliance proposals.

Only collected snapshot facts are read. Missing or denied resource details stay UNKNOWN.
"""
from __future__ import annotations

from . import register, result, unknown
from .facts import Unavailable, full_representation, get, guard, list_of_objects
from .fixtures import CASES


def _optional_api_field(item, name, *, complete=False):
    guard(item)
    coverage_map = item.get("_coverage", {})
    if not isinstance(coverage_map, dict):
        raise Unavailable("malformed field coverage")
    if name not in item and name not in coverage_map and not (complete or full_representation(item)):
        raise Unavailable("optional API field absence lacks full projection proof: " + name)
    literal = {"value": item.get(name)}
    if name in coverage_map:
        literal["_coverage"] = {"value": coverage_map[name]}
    return get(literal, "value")


def _versioned_bucket(item):
    if not full_representation(item):
        raise Unavailable("Cloud Storage bucket projection is not full")
    # storage.buckets.list projection=full omits versioning when disabled.
    versioning = _optional_api_field(item, "versioning")
    if versioning is None:
        return False
    if not isinstance(versioning, dict):
        raise Unavailable("malformed bucket versioning")
    return get(versioning, "enabled", bool)


@register("gcp_pci_bucket_0742bd5dc32c", "gcp", "hardening", "bucket",
          "Versioned Cloud Storage bucket has a supported lifecycle rule", "medium", "CP-9",
          "Add an owner-reviewed lifecycle rule for the versioned bucket, preserving required noncurrent versions and retention.")
def bucket_versioning_lifecycle(item, index):
    if not _versioned_bucket(item):
        return result(False, versioning_enabled=False)
    lifecycle = _optional_api_field(item, "lifecycle")
    if lifecycle is None:
        return result(True, versioning_enabled=True, lifecycle_rule_count=0)
    if not isinstance(lifecycle, dict):
        return unknown("malformed bucket lifecycle")
    rules = list_of_objects(get(lifecycle, "rule", list))
    if not rules:
        return result(True, versioning_enabled=True, lifecycle_rule_count=0)
    supported = {"Delete", "SetStorageClass", "AbortIncompleteMultipartUpload"}
    valid = []
    for rule in rules:
        action = get(rule, "action", dict)
        kind = get(action, "type", str)
        condition = get(rule, "condition", dict)
        if kind not in supported:
            return unknown("unrecognized lifecycle action", action=kind)
        if not condition:
            return unknown("lifecycle rule has no condition")
        valid.append(kind)
    return result(False, versioning_enabled=True, lifecycle_rule_count=len(valid), actions=valid)


@register("gcp_pci_bucket_3d76b0b0701e", "gcp", "hardening", "bucket",
          "Versioned Cloud Storage bucket declares positive retention", "medium", "CP-9",
          "Review legal and recovery periods, then set an approved positive bucket retention period.")
def bucket_versioning_retention(item, index):
    if not _versioned_bucket(item):
        return result(False, versioning_enabled=False)
    if _optional_api_field(item, "retentionPolicy") is None:
        return result(True, versioning_enabled=True, retention_seconds=None)
    policy = get(item, "retentionPolicy", dict)
    seconds = get(policy, "retentionPeriod")
    if isinstance(seconds, bool) or not isinstance(seconds, (str, int)):
        return unknown("malformed bucket retention period")
    if isinstance(seconds, str) and not seconds.isdecimal():
        return unknown("malformed bucket retention period")
    return result(int(seconds) <= 0, versioning_enabled=True, retention_seconds=int(seconds))


@register("gcp_pci_instance_template_2e26bed500fc", "gcp", "exposure", "instance_template",
          "Instance template declares no external network access configuration", "medium", "SC-7",
          "Remove public access configurations from the reviewed instance template and migrate consumers safely.")
def instance_template_no_public_ip(item, index):
    complete = full_representation(item)
    interfaces = list_of_objects(get(item, "properties.networkInterfaces", list))
    if not interfaces:
        return unknown("instance template has no network interface evidence")
    exposed, unresolved = [], False
    for offset, interface in enumerate(interfaces):
        # Compute omits each access-config array when that IP family has no
        # external access. IPv6 DIRECT_IPV6 is independent of IPv4 NAT.
        has_external_config = False
        for field in ("accessConfigs", "ipv6AccessConfigs"):
            if not complete and field not in interface and field not in interface.get("_coverage", {}):
                unresolved = True
                continue
            configs = _optional_api_field(interface, field, complete=complete)
            if configs is None and field not in interface:
                configs = []
            if not isinstance(configs, list) or any(not isinstance(value, dict) for value in configs):
                return unknown("malformed instance template " + field, interface=offset)
            has_external_config |= bool(configs)
        if has_external_config:
            exposed.append(offset)
    if unresolved and not exposed:
        return unknown("access configuration absence lacks full projection proof")
    return result(bool(exposed), external_interfaces=exposed, interface_count=len(interfaces),
                  semantics="Declared template configuration; running VM exposure is separate")


@register("gcp_pubsub_topic_cmek", "gcp", "hardening", "pubsub_topic",
          "Pub/Sub topic declares a customer-managed encryption key", "high", "SC-28",
          "Review key location and service-agent access, then set a customer-managed key on the topic.")
def pubsub_topic_cmek(item, index):
    get(item, "name", str)
    # Pub/Sub Topic.kmsKeyName is optional; omission on a complete topic means
    # the provider-managed default key, which does not meet a CMEK requirement.
    key = _optional_api_field(item, "kmsKeyName")
    if key is None and "kmsKeyName" in item:
        return unknown("null Pub/Sub KMS key name")
    if key is not None and not isinstance(key, str):
        return unknown("malformed Pub/Sub KMS key name")
    return result(not bool(key), kms_key_name=key or None)


def _dataset_access(item):
    if not full_representation(item):
        raise Unavailable("BigQuery dataset ACL was not collected with FULL view")
    # FULL datasets.get omits an empty access list; a partial list projection
    # cannot reach this branch because _representation must equal full.
    access = _optional_api_field(item, "access")
    if access is None:
        return []
    return list_of_objects(access)


def _public_member(row):
    fields = [row.get("specialGroup"), row.get("iamMember")]
    if any(field is not None and not isinstance(field, str) for field in fields):
        raise Unavailable("malformed BigQuery public ACL principal")
    return fields


@register("gcp_pci_bigquery_dataset_6017267cdf32", "gcp", "exposure", "bigquery_dataset",
          "BigQuery dataset has no public READER or WRITER ACL", "medium", "AC-3",
          "Remove the reviewed public READER or WRITER dataset access entry and grant only intended principals.")
def dataset_no_public_read_write(item, index):
    hits = []
    for row in _dataset_access(item):
        members = _public_member(row)
        if "role" not in row:
            # FULL dataset ACLs can contain authorized views, datasets, or
            # routines without a role or public principal.
            if any(value in {"allUsers", "allAuthenticatedUsers"} for value in members):
                return unknown("public BigQuery ACL entry has no role")
            if any(key in row for key in ("view", "dataset", "routine")):
                continue
            return unknown("BigQuery ACL entry has no role or authorized resource")
        role = get(row, "role", str)
        if role not in {"READER", "WRITER", "OWNER"} and not role.startswith("roles/"):
            return unknown("unrecognized BigQuery dataset ACL role", role=role)
        if role in {"READER", "WRITER"} and any(value in {"allUsers", "allAuthenticatedUsers"} for value in members):
            hits.append({"role": role, "principal": next(value for value in members
                                                        if value in {"allUsers", "allAuthenticatedUsers"})})
    return result(bool(hits), public_read_write_entries=hits)


@register("gcp_pci_bigquery_dataset_fb9fcc01d5b7", "gcp", "exposure", "bigquery_dataset",
          "BigQuery dataset ACL grants no access to allUsers", "medium", "AC-3",
          "Remove the exact allUsers dataset access entry and grant only reviewed authenticated principals.")
def dataset_no_all_users(item, index):
    hits = []
    for row in _dataset_access(item):
        members = _public_member(row)
        if "allUsers" in members:
            hits.append(get(row, "role", str))
    return result(bool(hits), all_users_roles=hits)


_full = {"_provenance": {"representation": "full"}}
CASES["gcp_pci_bucket_0742bd5dc32c"] = {
    "pass": {**_full, "versioning": {"enabled": True}, "lifecycle": {"rule": [
        {"action": {"type": "Delete"}, "condition": {"age": 90}}]}},
    "fail": {**_full, "versioning": {"enabled": True}, "lifecycle": {"rule": []}},
    "unknown": {**_full, "versioning": {"enabled": True},
        "_coverage": {"lifecycle": {"status": "denied"}}},
}
CASES["gcp_pci_bucket_3d76b0b0701e"] = {
    "pass": {**_full, "versioning": {"enabled": True},
        "retentionPolicy": {"retentionPeriod": "86400"}},
    "fail": {**_full, "versioning": {"enabled": True}},
    "unknown": {**_full, "versioning": {"enabled": True},
        "_coverage": {"retentionPolicy": {"status": "denied"}}},
}
CASES["gcp_pci_instance_template_2e26bed500fc"] = {
    "pass": {**_full, "properties": {"networkInterfaces": [
        {"network": "global/networks/private"}]}},
    "fail": {**_full, "properties": {"networkInterfaces": [
        {"accessConfigs": [{"type": "ONE_TO_ONE_NAT"}]}]}},
    "unknown": {"properties": {"networkInterfaces": [
        {"network": "global/networks/private"}]}},
}
CASES["gcp_pubsub_topic_cmek"] = {
    "pass": {"name": "projects/p/topics/t", "kmsKeyName":
        "projects/p/locations/europe/keyRings/r/cryptoKeys/k"},
    "fail": {"name": "projects/p/topics/t", **_full},
    "unknown": {"name": "projects/p/topics/t", "kmsKeyName": None},
}
_acl = {**_full, "access": []}
CASES["gcp_pci_bigquery_dataset_6017267cdf32"] = {
    "pass": _acl,
    "fail": {**_full, "access": [{"role": "READER", "specialGroup": "allAuthenticatedUsers"}]},
    "unknown": {**_full, "access": [{"specialGroup": "allUsers"}]},
}
CASES["gcp_pci_bigquery_dataset_fb9fcc01d5b7"] = {
    "pass": _acl,
    "fail": {**_full, "access": [{"role": "OWNER", "iamMember": "allUsers"}]},
    "unknown": {**_full, "_coverage": {"access": {"status": "denied"}}},
}
