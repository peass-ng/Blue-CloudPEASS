"""Metadata-only key/encryption/date declarations at the captured snapshot clock."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import re
from . import register, result, unknown
from .facts import get, optional, omitted, complete_items, Unavailable, list_of_objects
from .fixtures import CASES

IDS, REFERENCE_SPECS = [], {}


def check(query, kind, function, good, bad, *, dependencies=None):
    cid = "gcp.ports." + query
    IDS.append(cid)
    register(cid, "gcp", "hardening", kind, query.replace("_", " "), "medium", "SC-12",
        "Review key/configuration metadata and the immutable evidence window; never infer secret compromise or perform key/permission actions.",
        dependencies=dependencies)(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid
    return cid


def parse_time(value):
    if not isinstance(value, str):
        raise Unavailable("timestamp unavailable")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise Unavailable("timestamp timezone missing")
    return parsed.astimezone(timezone.utc)


def age(query, kind, field, user_managed=False):
    def evaluate(item, index):
        if user_managed:
            key_type = get(item, "keyType", str)
            if key_type == "SYSTEM_MANAGED":
                return "NOT_APPLICABLE", {"reason": "Provider-managed key outside user-managed age policy"}
            if key_type != "USER_MANAGED":
                return unknown("unrecognized key type")
        observed = item.get("_provenance", {}).get("collected_at") or index.get("context", {}).get("created_at")
        captured = parse_time(observed)
        created = parse_time(get(item, field, str))
        cutoff = datetime.combine(captured.date() - timedelta(days=90), datetime.min.time(), tzinfo=timezone.utc)
        return result(created <= cutoff, created_at=created.isoformat(), observed_at=captured.isoformat(),
            cutoff=cutoff.isoformat(), semantics="Key age metadata at captured UTC date, not current wall clock or activity proof")
    good = {field: "2026-10-01T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T12:00:00Z"}}
    bad = {field: "2026-01-01T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T12:00:00Z"}}
    if user_managed:
        good["keyType"] = bad["keyType"] = "USER_MANAGED"
    check(query, kind, evaluate, good, bad)


age("iam_api_key_age_90", "api_key", "createTime")
age("iam_service_account_key_age_90", "service_account_key", "validAfterTime", True)


def kms_period(item, index):
    # Applicability first: non-ENCRYPT_DECRYPT keys carry no primary at all
    # ("For other keys, this field will be omitted"), and a full key with no
    # primary version cannot encrypt; both match gcp.reviewed.kms rotation.
    from .gcp_extended import rotation_applicability, INACTIVE_PRIMARY
    state = item.get("primary", {}).get("state") if isinstance(item.get("primary"), dict) else None
    if state in INACTIVE_PRIMARY:
        return "NOT_APPLICABLE", {"primary_state": state}
    reason = rotation_applicability(item)
    if reason:
        return "NOT_APPLICABLE", {"reason": reason, "primary_state": (item.get("primary") or {}).get("state")}
    state = get(item, "primary.state", str)
    if state != "ENABLED":
        return unknown("primary version state unrecognized")
    # Cloud KMS omits rotationPeriod when automatic rotation is not configured;
    # only a full (unmasked) CryptoKey representation proves that omission.
    period = omitted(item, "rotationPeriod", "0s", str)
    if not re.fullmatch(r"[0-9]+s", period):
        return unknown("source integer protobuf duration policy does not cover this value")
    seconds = int(period[:-1])
    return result(not 0 < seconds <= 7776000, rotation_seconds=seconds,
        semantics="Declared automatic period; key purpose and next rotation timing are separate")


check("kms_key_rotated_within_90_day", "kms_key", kms_period,
    {"primary": {"state": "ENABLED"}, "purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s"},
    {"primary": {"state": "ENABLED"}, "purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776001s"})


def api_targets(item, index):
    restrictions = get(item, "restrictions", dict)
    targets = optional(restrictions, "apiTargets", [], list)
    for target in list_of_objects(targets):
        service = get(target, "service", str)
        if not service:
            return unknown("empty API restriction service")
    return result(not targets or any(target["service"] == "cloudapis.googleapis.com" for target in targets),
        restricted_services=[target["service"] for target in targets])


check("iam_api_key_restricts_apis", "api_key", api_targets,
    {"restrictions": {"apiTargets": [{"service": "storage.googleapis.com"}]}}, {"restrictions": {"apiTargets": []}})


def caller_restrictions(item, index):
    restrictions = get(item, "restrictions", dict)
    modes = [key for key in ("serverKeyRestrictions", "browserKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions") if key in restrictions]
    if not modes:
        return result(True, reason="no caller restriction declaration")
    if len(modes) != 1:
        return unknown("API key caller restrictions must use one mode")
    mode = modes[0]
    body = get(restrictions, mode, dict)
    field = {"serverKeyRestrictions": "allowedIps", "browserKeyRestrictions": "allowedReferrers",
             "androidKeyRestrictions": "allowedApplications", "iosKeyRestrictions": "allowedBundleIds"}[mode]
    allowed = get(body, field, list)
    if mode == "androidKeyRestrictions":
        list_of_objects(allowed)
    elif any(not isinstance(value, str) for value in allowed):
        raise Unavailable("malformed caller restriction strings")
    broad = any(value in ("0.0.0.0", "0.0.0.0/0", "::", "::0", "::/0", "*", "*.[TLD]/*", "*.[TLD]") for value in allowed if isinstance(value, str))
    return result(not allowed or broad, restriction_mode=mode, allowed=allowed,
        semantics="Caller restriction declarations; no key string or request execution is collected")


check("iam_api_key_restricts_websites_hosts_apps", "api_key", caller_restrictions,
    {"restrictions": {"serverKeyRestrictions": {"allowedIps": ["192.0.2.1"]}}},
    {"restrictions": {"serverKeyRestrictions": {"allowedIps": ["::/0"]}}})


def encryption(query, kind, path, view=False, canonical=None):
    if canonical:
        IDS.append(canonical)
        REFERENCE_SPECS[query] = canonical
        return
    def evaluate(item, index):
        if view:
            variant = get(item, "type", str)
            if variant == "VIEW":
                return "NOT_APPLICABLE", {"reason": "Logical view stores no table data"}
        value = get(item, path, str)
        return result(not bool(value), key_reference=value,
            semantics="Declared customer-managed encryption reference, not cryptographic key material")
    def fixture(value):
        result = {}
        target = result
        parts = path.split(".")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
        if view:
            result["type"] = "TABLE"
        return result
    check(query, kind, evaluate, fixture("projects/p/locations/global/keyRings/r/cryptoKeys/k"), fixture(""))


encryption("bigquery_dataset_encrypted_with_cmk", "bigquery_dataset", "defaultEncryptionConfiguration.kmsKeyName", canonical="gcp.reviewed.bigquery.cmek")
encryption("bigquery_table_encrypted_with_cmk", "bigquery_table", "encryptionConfiguration.kmsKeyName", True)
encryption("dataproc_cluster_encryption_with_cmek", "dataproc_cluster", "config.encryptionConfig.gcePdKmsKeyName")


def account_keys(item, index):
    email = get(item, "email", str)
    name = get(item, "name", str)
    keys = complete_items(index, "service_account_key")
    linked = [key for key in keys if key.get("serviceAccount") in (name, email) or str(key.get("name", "")).startswith(name + "/keys/")]
    user = [key for key in linked if get(key, "keyType", str) == "USER_MANAGED"]
    return result(bool(user), service_account=email, user_managed_keys=[key.get("name") for key in user],
        semantics="Known complete key metadata; absence does not establish activity or effective permissions")


cid = check("iam_service_account_gcp_managed_key", "service_account", account_keys,
    {"name": "projects/p/serviceAccounts/a", "email": "a@p.iam.gserviceaccount.com"},
    {"name": "projects/p/serviceAccounts/b", "email": "b@p.iam.gserviceaccount.com"}, dependencies=["service_account", "service_account_key"])
CASES[cid]["index"] = {"collections": {"service_account_key": [{"scope": "projects/p", "status": "collected"}]},
    "service_account_key": [{"data": {"name": "projects/p/serviceAccounts/b/keys/k", "serviceAccount": "projects/p/serviceAccounts/b", "keyType": "USER_MANAGED"}}]}
