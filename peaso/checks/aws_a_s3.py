"""S3 native configuration predicates with proven absence."""
from . import alias_check, register, result, unknown
from .facts import get, list_of_objects
from .fixtures import CASES

NATIVE_IDS = []


@register("aws.a.s3.default_encryption_configuration", "aws", "hardening", "bucket", "S3 bucket has native default encryption configuration",
    "medium", "SC-13", "Review the native default encryption configuration and intended key policy separately.")
def encryption(item, index):
    config = get(item, "Encryption", dict)
    if config.get("collection_status") == "empty" and config.get("absent") is True:
        return result(True, default_encryption_configuration=False)
    rules = list_of_objects(get(config, "ServerSideEncryptionConfiguration.Rules", list))
    if not rules:
        return unknown("malformed empty native default encryption rules")
    for rule in rules:
        get(rule, "ApplyServerSideEncryptionByDefault.SSEAlgorithm", str)
    return result(False, default_encryption_configuration=True, rule_count=len(rules), semantics="Exact source configuration-presence policy; no stronger KMS-only constraint")
CASES["aws.a.s3.default_encryption_configuration"] = {"pass": {"Encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}},
    "fail": {"Encryption": {"collection_status": "empty", "absent": True}}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.s3.default_encryption_configuration")


@register("aws.a.s3.mfa_delete_enabled", "aws", "hardening", "bucket", "S3 bucket has MFA Delete enabled",
    "medium", "CP-9", "Review MFA Delete as a separate setting from versioning and object-lock retention.")
def mfa_delete(item, index):
    config = get(item, "Versioning", dict)
    if "MFADelete" not in config:
        if config.get("collection_status") == "collected":
            return result(True, mfa_delete="not_reported")
        return unknown("MFA Delete absence not proven")
    state = get(config, "MFADelete", str)
    if state not in {"Enabled", "Disabled"}:
        return unknown("unrecognized native MFA Delete state")
    return result(state != "Enabled", mfa_delete=state)
CASES["aws.a.s3.mfa_delete_enabled"] = {"pass": {"Versioning": {"MFADelete": "Enabled"}}, "fail": {"Versioning": {"collection_status": "collected"}}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.s3.mfa_delete_enabled")
alias_check("aws.a.s3.bucket_account_public_blocks", "aws.s3.public_access_block")
