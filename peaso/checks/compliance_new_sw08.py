"""Signed GCP policy checks over complete, project-scoped read-only facts.

Operator policy is carried in context.metadata.compliance_policy with an exact
scope and collected status. Unavailable policy or inventory is never success.
"""
from __future__ import annotations

import json
import re
from decimal import Decimal
from collections import Counter
from datetime import datetime
from urllib.parse import quote

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, omitted
from .gcp_api_key_service_names_native import canonical_service, canonical_target


def _rows(index, kind, scope):
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("complete scoped collection unavailable: " + kind)
    envelope = get({"envelope": envelopes[0]}, "envelope", dict)
    if (envelope.get("type") != kind or envelope.get("scope") != scope or
            envelope.get("status") not in ("collected", "empty") or
            envelope.get("coverage_status", "collected") not in ("collected", "empty")):
        raise Unavailable("complete scoped collection unavailable: " + kind)
    rows = complete_items(index, kind)
    recorded = list_of_objects(get(envelope, "items", list))
    encode = lambda row: json.dumps(row, sort_keys=True, separators=(",", ":"))
    if (Counter(map(encode, rows)) != Counter(map(encode, recorded)) or
            envelope.get("status") == "empty" and rows):
        raise Unavailable("collection projection differs from envelope")
    names = set()
    for resource, row in zip(get(index, kind, list), rows):
        if (get(resource, "scope", str) != scope or get(resource, "type", str) != kind or
                resource.get("provider", "gcp") != "gcp" or
                get(row, "_provenance.scope", str) != scope):
            raise Unavailable("foreign resource fact")
        name = get(row, "name", str)
        if not name or name in names:
            raise Unavailable("duplicate or malformed resource identity")
        names.add(name)
    return rows


def _inventory(item, index, kind):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "gcp":
        raise Unavailable("GCP provider authority unavailable")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"projects/[A-Za-z0-9_-]+", scope):
        raise Unavailable("project scope unavailable")
    rows = _rows(index, kind, scope)
    if item not in rows:
        raise Unavailable("resource is not in the complete scoped inventory")
    return scope


def _policy(index, scope):
    metadata = get(get(index, "context", dict), "metadata", dict)
    policy = get(metadata, "compliance_policy", dict)
    if policy.get("status") != "collected" or policy.get("scope") != scope:
        raise Unavailable("collected project-bound compliance policy unavailable")
    return policy


def _names(policy, field):
    values = get(policy, field, list)
    if any(not isinstance(x, str) or not x.strip() for x in values) or len(values) != len(set(values)):
        raise Unavailable("malformed policy list: " + field)
    return set(values)


def _workbench(item, index):
    scope = _inventory(item, index, "workbench_instance")
    name = get(item, "name", str)
    if not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/instances/[^/]+", name):
        raise Unavailable("Workbench instance identity malformed or foreign")
    return name, _policy(index, scope)


def _sensitivity(policy, name):
    values = get(policy, "workbench_sensitive", dict)
    if name not in values or type(values[name]) is not bool:
        raise Unavailable("Workbench sensitivity classification unavailable")
    return values[name]


def _metadata_flag(item, flag):
    value = get(item, "gceSetup.metadata." + flag, str)
    if value not in ("true", "false"):
        raise Unavailable("unrecognized Workbench metadata flag: " + flag)
    return value == "true"


def _image_ref(value, kind):
    if not isinstance(value, dict):
        raise Unavailable("malformed Workbench image")
    if kind == "vmImage":
        project = get(value, "project", str)
        selectors = [key for key in ("family", "name") if key in value]
        if not project or len(selectors) != 1 or "imageFamily" in value or "imageName" in value:
            raise Unavailable("Workbench v2 VM image identity unavailable")
        selector = get(value, selectors[0], str)
        if not selector:
            raise Unavailable("Workbench VM image selector empty")
        return "vm:" + project + "/" + selectors[0] + "/" + selector
    repository = get(value, "repository", str)
    selector = get(value, "tag", str)
    if not repository or not selector or "digest" in value:
        raise Unavailable("Workbench v2 container image identity unavailable")
    return "container:" + repository + "/" + selector


def _approved_image(item, index):
    name, policy = _workbench(item, index)
    approved = _names(policy, "approved_workbench_images")
    setup = get(item, "gceSetup", dict)
    refs = [_image_ref(get(setup, kind, dict), kind) for kind in ("vmImage", "containerImage") if kind in setup]
    if len(refs) != 1:
        return unknown("unique Workbench image metadata unavailable", instance=name)
    return result(any(ref not in approved for ref in refs), instance=name, images=refs)


def _approved_vpc(item, index):
    name, policy = _workbench(item, index)
    approved = _names(policy, "approved_workbench_networks")
    interfaces = get(item, "gceSetup.networkInterfaces", list)
    if not interfaces:
        return unknown("Workbench network metadata unavailable", instance=name)
    networks = [get(interface, "network", str) for interface in interfaces]
    if any(not network for network in networks):
        return unknown("Workbench network identity unavailable", instance=name)
    return result(any(network not in approved for network in networks), instance=name, networks=networks)


def _sensitive_flag(item, index, field, metadata=False):
    name, policy = _workbench(item, index)
    sensitive = _sensitivity(policy, name)
    if not sensitive:
        return "NOT_APPLICABLE", {"instance": name, "reason": "policy classifies instance as nonsensitive"}
    disabled = _metadata_flag(item, field) if metadata else get(item, "gceSetup." + field, bool)
    return result(not disabled, instance=name, sensitive=True, configured=disabled)


def _exception_flag(item, index, flag):
    name, policy = _workbench(item, index)
    sensitive = _sensitivity(policy, name)
    disabled = _metadata_flag(item, flag)
    if sensitive:
        return result(not disabled, instance=name, sensitive=True, disabled=disabled)
    if disabled:
        return result(False, instance=name, sensitive=False, disabled=True)
    exceptions = get(policy, "approved_workbench_exceptions", dict)
    if name in exceptions and (not isinstance(exceptions[name], dict) or
                               type(exceptions[name].get(flag)) is not bool):
        return unknown("malformed Workbench exception decision", instance=name)
    approved = exceptions.get(name, {}).get(flag, False)
    return result(not disabled and not approved, instance=name, sensitive=False,
                  disabled=disabled, approved_exception=approved)


def _classification(item, index):
    scope = _inventory(item, index, "bucket")
    name = get(item, "name", str)
    policy = _policy(index, scope)
    in_scope = _names(policy, "classified_buckets")
    if name not in in_scope:
        return "NOT_APPLICABLE", {"bucket": name, "reason": "bucket outside approved classification scope"}
    key = get(policy, "required_classification_key", str)
    if not key:
        raise Unavailable("classification key unavailable")
    approved = _names(policy, "approved_classification_values")
    if "labels" in item or "labels" in item.get("_coverage", {}):
        labels = get(item, "labels", dict)
    elif get(item, "_provenance.representation", str) == "full":
        labels = {}  # projection=full omits the map when no labels are set.
    else:
        raise Unavailable("bucket labels unavailable in partial representation")
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items()):
        raise Unavailable("malformed bucket labels")
    return result(labels.get(key) not in approved, bucket=name, classification=labels.get(key))


def _hsm(item, index):
    scope = _inventory(item, index, "kms_key")
    name = get(item, "name", str)
    if not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+", name):
        raise Unavailable("CryptoKey identity malformed or foreign")
    policy = _policy(index, scope)
    designated = _names(policy, "designated_hsm_keys")
    if name not in designated:
        return "NOT_APPLICABLE", {"key": name, "reason": "key is not HSM designated"}
    allowed = {"HSM"}
    external = policy.get("approved_external_vpc_keys", [])
    if not isinstance(external, list) or any(not isinstance(x, str) for x in external):
        raise Unavailable("external VPC key policy malformed")
    if name in external:
        allowed.add("EXTERNAL_VPC")
    level = get(item, "primary.protectionLevel", str)
    if level not in ("SOFTWARE", "HSM", "EXTERNAL", "EXTERNAL_VPC"):
        raise Unavailable("unknown KMS protection level")
    return result(level not in allowed, key=name, protection_level=level)


def _versions(item, index):
    scope = _inventory(item, index, "kms_key")
    name = get(item, "name", str)
    if not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+", name):
        raise Unavailable("CryptoKey identity malformed or foreign")
    versions = _rows(index, "kms_key_version", scope)
    selected = []
    seen = set()
    for version in versions:
        version_name = get(version, "name", str)
        if not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+", version_name) or version_name in seen:
            raise Unavailable("foreign or inconsistent CryptoKeyVersion fact")
        seen.add(version_name)
        if version_name.startswith(name + "/cryptoKeyVersions/"):
            selected.append(version)
    scheduled = []
    for version in selected:
        state = get(version, "state", str)
        if state not in ("PENDING_GENERATION", "ENABLED", "DISABLED", "DESTROY_SCHEDULED", "DESTROYED", "PENDING_IMPORT", "IMPORT_FAILED", "GENERATION_FAILED"):
            raise Unavailable("unrecognized CryptoKeyVersion state")
        if state == "DESTROY_SCHEDULED":
            destroy = get(version, "destroyTime", str)
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})", destroy):
                raise Unavailable("malformed scheduled destruction time")
            try:
                datetime.fromisoformat(destroy.replace("Z", "+00:00"))
            except ValueError:
                raise Unavailable("malformed scheduled destruction time")
            scheduled.append(version["name"])
    return result(bool(scheduled), key=name, scheduled_versions=scheduled)


def _logging_retention(item, index):
    scope = _inventory(item, index, "logging_bucket")
    name = get(item, "name", str)
    if not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/buckets/[^/]+", name):
        raise Unavailable("Logging bucket identity malformed or foreign")
    context = get(index, "context", dict)
    metadata = context.get("metadata", {})
    if not isinstance(metadata, dict):
        raise Unavailable("malformed snapshot metadata")
    threshold = metadata.get("MinRetentionTime", 365)
    if type(threshold) is not int or threshold <= 0:
        raise Unavailable("invalid MinRetentionTime")
    days = get(item, "retentionDays", int)
    if days < 0:
        raise Unavailable("invalid Logging bucket retention")
    return result(days < threshold, bucket=name, retention_days=days, min_retention_days=threshold)


# Cloud KMS v1 CryptoKeyVersionAlgorithm, reviewed against the provider enum.
_KMS_ALGORITHMS = {
    "GOOGLE_SYMMETRIC_ENCRYPTION", "EXTERNAL_SYMMETRIC_ENCRYPTION", "AES_256_KWP",
    *(f"AES_{bits}_{mode}" for bits in (128, 256) for mode in ("GCM", "CBC", "CTR")),
    *(f"RSA_SIGN_{padding}_{bits}_SHA256" for padding in ("PSS", "PKCS1") for bits in (2048, 3072, 4096)),
    "RSA_SIGN_PSS_4096_SHA512", "RSA_SIGN_PKCS1_4096_SHA512",
    *(f"RSA_SIGN_RAW_PKCS1_{bits}" for bits in (2048, 3072, 4096)),
    *(f"RSA_DECRYPT_OAEP_{bits}_{digest}" for bits in (2048, 3072, 4096) for digest in ("SHA1", "SHA256")),
    "RSA_DECRYPT_OAEP_4096_SHA512", "EC_SIGN_P256_SHA256", "EC_SIGN_P384_SHA384",
    "EC_SIGN_SECP256K1_SHA256", "EC_SIGN_ED25519",
    *(f"HMAC_SHA{bits}" for bits in (1, 224, 256, 384, 512)),
    "ML_KEM_768", "ML_KEM_1024", "KEM_XWING", "KEM_ECDH_P256", "KEM_ECDH_P384",
    *(f"PQ_SIGN_ML_DSA_{level}{suffix}" for level in (44, 65, 87) for suffix in ("", "_EXTERNAL_MU")),
    "PQ_SIGN_SLH_DSA_SHA2_128S", "PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256",
}


def _approved_algorithm(item, index):
    scope = _inventory(item, index, "kms_key_version")
    name = get(item, "name", str)
    if not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+", name):
        raise Unavailable("CryptoKeyVersion identity malformed or foreign")
    policy = _policy(index, scope)
    approved = _names(policy, "approved_algorithms")
    state = get(item, "state", str)
    if state not in ("PENDING_GENERATION", "ENABLED", "DISABLED", "DESTROY_SCHEDULED", "DESTROYED", "PENDING_IMPORT", "IMPORT_FAILED", "GENERATION_FAILED"):
        raise Unavailable("unrecognized CryptoKeyVersion state")
    if state != "ENABLED":
        return "NOT_APPLICABLE", {"version": name, "reason": "version is not ENABLED"}
    algorithm = get(item, "algorithm", str)
    if algorithm not in _KMS_ALGORITHMS:
        raise Unavailable("version algorithm unavailable or unrecognized")
    return result(algorithm not in approved, version=name, algorithm=algorithm)


def _artifact_cleanup(item, index):
    scope = _inventory(item, index, "artifact_repository")
    name = get(item, "name", str)
    if not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/repositories/[^/]+", name):
        raise Unavailable("Artifact Registry repository identity malformed or foreign")
    policy = _policy(index, scope)
    maximum = get(policy, "max_artifact_age", int)
    if maximum <= 0:
        raise Unavailable("invalid max_artifact_age seconds")
    dry_run = omitted(item, "cleanupPolicyDryRun", False, bool)
    policies = omitted(item, "cleanupPolicies", {}, dict)
    if not policies or any(not isinstance(key, str) or not key or not isinstance(value, dict)
                           for key, value in policies.items()):
        if policies:
            raise Unavailable("malformed cleanup policy map")
        return result(True, repository=name, reason="no cleanup policies") if not dry_run else result(True, repository=name, reason="cleanup is dry-run")
    qualifying = []
    for key, value in policies.items():
        action = get(value, "action", str)
        if action not in ("DELETE", "KEEP"):
            raise Unavailable("unrecognized cleanup policy action")
        if "condition" in value and "mostRecentVersions" in value:
            raise Unavailable("conflicting cleanup condition union")
        if "condition" in value:
            condition = get(value, "condition", dict)
            for field in ("tagPrefixes", "versionNamePrefixes", "packageNamePrefixes"):
                if field in condition:
                    values = get(condition, field, list)
                    if any(not isinstance(x, str) or not x for x in values):
                        raise Unavailable("malformed cleanup condition prefix")
            if "tagState" in condition and get(condition, "tagState", str) not in {"TAG_STATE_UNSPECIFIED", "TAGGED", "UNTAGGED", "ANY"}:
                raise Unavailable("unrecognized cleanup tag state")
            for field in ("olderThan", "newerThan"):
                if field in condition and not re.fullmatch(r"[0-9]+(?:\.[0-9]{1,9})?s", get(condition, field, str)):
                    raise Unavailable("malformed cleanup duration")
        elif "mostRecentVersions" in value and action == "KEEP":
            recent = get(value, "mostRecentVersions", dict)
            if get(recent, "keepCount", int) <= 0:
                raise Unavailable("malformed cleanup keep count")
        else:
            raise Unavailable("cleanup policy condition unavailable")
        if action != "DELETE":
            continue
        condition = get(value, "condition", dict)
        if "mostRecentVersions" in value:
            raise Unavailable("conflicting cleanup condition union")
        # A valid DELETE condition need not contain an age constraint.
        older = omitted({**condition, "_provenance": item.get("_provenance", {})}, "olderThan", "", str)
        if not older:
            continue
        match = re.fullmatch(r"([0-9]+(?:\.[0-9]{1,9})?)s", older)
        if not match:
            raise Unavailable("unrecognized cleanup policy duration")
        if Decimal(match.group(1)) <= maximum:
            qualifying.append(key)
    return result(dry_run or not qualifying, repository=name,
                  qualifying_delete_policies=sorted(qualifying), dry_run=dry_run)


def _api_key_services(item, index):
    scope = _inventory(item, index, "api_key")
    key_name = get(item, "name", str)
    if not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/keys/[^/]+", key_name):
        raise Unavailable("API key identity malformed or foreign")
    targets = get(item, "restrictions.apiTargets", list)
    if not targets:
        return unknown("API key has no explicit service targets", api_key=key_name)
    requested = []
    for target in targets:
        service = get(target, "service", str)
        try:
            requested.append(canonical_target(service))
        except ValueError as exc:
            raise Unavailable(str(exc)) from exc
    rows = _rows(index, "service_usage", scope)
    states = {}
    for row in rows:
        state = get(row, "state", str)
        if get(row, "_provenance.scope", str) != scope or state not in ("ENABLED", "DISABLED"):
            raise Unavailable("malformed or foreign Service Usage fact")
        try:
            service = canonical_service(row, scope)
        except ValueError as exc:
            raise Unavailable(str(exc)) from exc
        if service in states:
            raise Unavailable("duplicate Service Usage DNS identity")
        states[service] = state
    if any(service not in states for service in requested):
        return unknown("target service absent from selected Service Usage inventory", api_key=key_name)
    disabled = sorted(set(service for service in requested if states[service] == "DISABLED"))
    if disabled:
        return result(True, api_key=key_name, disabled_target_services=disabled)
    return unknown("enabled service does not establish active key use", api_key=key_name)


def _mysql_admin(item, index):
    scope = _inventory(item, index, "sql_user")
    identity = get(item, "name", str)
    if not identity.startswith(scope + "/instances/") or "/users/" not in identity:
        raise Unavailable("SQL user identity belongs to another project")
    instance_id = get(item, "instanceId", str)
    if not instance_id or not identity.startswith(scope + "/instances/" + instance_id + "/users/"):
        raise Unavailable("SQL user parent instance identity unavailable")
    instances = _rows(index, "sql_instance", scope)
    by_name = {}
    for instance in instances:
        instance_name = get(instance, "name", str)
        if (not instance_name or instance_name in by_name or
                get(instance, "_provenance.scope", str) != scope):
            raise Unavailable("foreign or duplicate SQL instance")
        by_name[instance_name] = instance
    if instance_id not in by_name:
        raise Unavailable("SQL user parent instance absent")
    version = get(by_name[instance_id], "databaseVersion", str)
    if not re.fullmatch(r"MYSQL_[0-9]+(?:_[0-9]+)*", version):
        if re.fullmatch(r"(?:POSTGRES_[0-9]+(?:_[0-9]+)?|SQLSERVER_[0-9]+_(?:STANDARD|ENTERPRISE|EXPRESS|WEB))", version):
            return "NOT_APPLICABLE", {"sql_user": identity, "reason": "parent instance is not MySQL"}
        raise Unavailable("unsupported SQL instance database version")
    username = get(item, "userName", str)
    host = get(item, "host", str)
    user_type = get(item, "type", str)
    known_types = {"BUILT_IN", "CLOUD_IAM_USER", "CLOUD_IAM_SERVICE_ACCOUNT", "CLOUD_IAM_GROUP",
                   "CLOUD_IAM_GROUP_USER", "CLOUD_IAM_GROUP_SERVICE_ACCOUNT"}
    expected_identity = scope + "/instances/" + instance_id + "/users/" + quote(username, safe="") + "@" + quote(host, safe="")
    if not username or not host or user_type not in known_types or identity != expected_identity:
        raise Unavailable("SQL user identity fields unavailable")
    failed = (username == "root" or user_type == "BUILT_IN") and host in ("%", "0.0.0.0/0")
    return result(failed, sql_user=identity, user_name=username, host=host, user_type=user_type)


# The signed ledger carries domain-specific categories that the current
# register validator does not yet recognize. Register safely, then preserve
# exact signed metadata on its frozen Check object for the integrator.
_DEFINITIONS = []


def _install(identifier, category, kind, title, severity, hint, sha, evaluator, dependencies=None):
    @register(identifier, "gcp", category if category in {"hardening", "exposure", "least_privilege", "iam_graph", "network"} else "hardening",
              kind, title, severity, "CM-6", hint, dependencies=dependencies or [kind])
    def check(item, index):
        return evaluator(item, index)
    check.__name__ = identifier.replace(".", "_")
    registered = CHECKS[-1]
    if registered.id != identifier:
        raise RuntimeError("unexpected registry order")
    object.__setattr__(registered, "category", category)
    _DEFINITIONS.append((identifier, sha))
    return check

_install('gcp_workbench_approved_image', 'compute', 'workbench_instance', 'Workbench instance uses an unapproved image', 'high', 'Recreate the Workbench instance with gceSetup.vmImage or containerImage from approved_workbench_images.', 'ed670835e571526ea18d080d056059e61fe87326d152bc4546d4f6e0fc2fc4bd', _approved_image, dependencies=['workbench_instance'])
_install('gcp_workbench_approved_vpc', 'network', 'workbench_instance', 'Workbench instance uses an unapproved VPC', 'medium', 'Move or recreate the Workbench instance on a VPC in approved_workbench_networks.', 'f4f5feed1c78426146fec3ce0bbcaf09f039ab7bee7f39a175be69cbf5c0c111', _approved_vpc, dependencies=['workbench_instance'])
_install('gcp_workbench_download_disabled', 'compute', 'workbench_instance', 'Sensitive Workbench instance allows file downloads', 'medium', 'Set gceSetup.metadata.notebook-disable-downloads=true on sensitive Workbench instances.', 'a604366f60551960af7b76911769643a196549adeaf205f383804b4dc1097678', lambda i,x: _sensitive_flag(i,x,'notebook-disable-downloads',True), dependencies=['workbench_instance'])
_install('gcp_workbench_no_public_ip', 'network', 'workbench_instance', 'Sensitive Workbench instance permits a public IP', 'medium', 'Set gceSetup.disablePublicIp=true on sensitive Workbench instances and use private access.', 'bf7b3cc245cd475915b7ef6210af00f072ab2e5eb723223856befcf7aae7db8d', lambda i,x: _sensitive_flag(i,x,'disablePublicIp'), dependencies=['workbench_instance'])
_install('gcp_workbench_root_disabled', 'compute', 'workbench_instance', 'Workbench root access violates classification policy', 'medium', 'Set gceSetup.metadata.notebook-disable-root=true on sensitive Workbench instances; document nonsensitive exceptions.', '16d65c05518f4aa17fd4390611160fe5fb1ffc0f96b1503242e4a86bf32362a0', lambda i,x: _exception_flag(i,x,'notebook-disable-root'), dependencies=['workbench_instance'])
_install('gcp_workbench_terminal_disabled', 'compute', 'workbench_instance', 'Workbench terminal access violates classification policy', 'medium', 'Set gceSetup.metadata.notebook-disable-terminal=true on sensitive Workbench instances; document nonsensitive exceptions.', '020c75fd76b06549135f21c1499fee6172b1e433cbe62980286065dc72a10f69', lambda i,x: _exception_flag(i,x,'notebook-disable-terminal'), dependencies=['workbench_instance'])
_install('gcp_c5_classification_label', 'asset_management', 'bucket', 'Cloud Storage bucket classification label', 'medium', 'Set the approved classification label and value on each in-scope Cloud Storage bucket with gcloud storage buckets update --update-labels.', 'eee3ae9bd7d11ebffeb52ee72c8704e4f322c4db72810645762bc9e7556e5fdc', _classification, dependencies=['bucket'])
_install('gcp_c5_kms_hsm', 'key_management', 'kms_key', 'HSM-protected KMS key', 'medium', 'Create designated Cloud KMS keys with protectionLevel=HSM, or approved EXTERNAL_VPC, and migrate protected workloads.', '70698b8e45c47909338af939b701513e16da2d72a114777777772153c12817b7', _hsm, dependencies=['kms_key'])
_install('gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650', 'hardening', 'kms_key', 'KMS key version is scheduled for destruction', 'medium', 'Cancel destruction of any KMS version in DESTROY_SCHEDULED state if deletion is not approved.', '8e9aff3409ed1c0ce2b30b898508439cb18006ec1f7b8b2ee94287b8d37c82e8', _versions, dependencies=['kms_key', 'kms_key_version'])
_install('gcp_pci_asset_6ee2fef37d98', 'retention', 'logging_bucket', 'Cloud Logging bucket retention meets minimum', 'medium', 'Set each Cloud Logging bucket retentionDays to at least configured MinRetentionTime (365 days by default).', '076d04357099e5a69960c32b2106b4ff0fba622a6e2f2d1ee1b7068a49dcc276', _logging_retention, dependencies=['logging_bucket'])
_install('gcp_kms_approved_algorithm', 'encryption', 'kms_key_version', 'KMS key version uses an unapproved algorithm', 'high', 'Rotate ENABLED KMS key versions using an algorithm in approved_algorithms and disable unapproved versions.', '71068c89df5053ff3a950dd33b6fc4b8af1896186e8ae7789a19714c9bbc6166', _approved_algorithm, dependencies=['kms_key_version'])
_install('gcp_artifact_registry_cleanup_policy', 'data_lifecycle', 'artifact_repository', 'Artifact repository lacks age-based cleanup', 'medium', 'Add an Artifact Registry DELETE cleanupPolicy with an age condition at or below the approved max_artifact_age and disable dry run.', '73e2c420470a52c7a17b69a6b305a0b3b5cce7fe14a20f3102291682d56ae4e1', _artifact_cleanup, dependencies=['artifact_repository'])
_install('gcp.apikeys.active_service_restrictions', 'least_privilege', 'api_key', 'API keys target only active enabled services', 'medium', "In APIs & Services > Credentials, edit the key's API restrictions to remove disabled services; delete unused keys.", '7c91d652644f5e1644dacb522fc4fd15d2f30eabdbe7ec4c9481e87fa85c69db', _api_key_services, dependencies=['api_key', 'service_usage'])
_install('gcp.sql.mysql_admin_account_posture', 'least_privilege', 'sql_user', 'MySQL administrative accounts restrict remote connections', 'high', 'Restrict MySQL root or built-in account host from % and 0.0.0.0/0 using Cloud SQL Users settings.', 'ebded375bd9e341806de99ef9f490c3b17aec3c51e4fae9b3ff2beb57ff2e34c', _mysql_admin, dependencies=['sql_user', 'sql_instance'])
