"""S3 native configuration predicates with proven absence and scoped joins."""
from . import register, result, unknown
from .facts import get, list_of_objects, Unavailable
from .fixtures import CASES
from .aws_a_facts import complete_items, scope_fixture

NATIVE_IDS = []
BLOCKS = ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")


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


def block_settings(config):
    get(config, "collection_status", str) if "collection_status" in config else None
    if config.get("collection_status") == "empty" and config.get("absent") is True:
        return {field: False for field in BLOCKS}
    values = get(config, "PublicAccessBlockConfiguration", dict)
    return {field: get(values, field, bool) for field in BLOCKS}


@register("aws.a.s3.bucket_account_public_blocks", "aws", "exposure", "bucket", "S3 bucket or verified account enables each Public Access Block setting",
    "high", "AC-3", "Enable all four Public Access Block controls at bucket or account scope; review effective access separately.", dependencies=["bucket", "s3_account_public_access_block"])
def public_blocks(item, index):
    bucket = block_settings(get(item, "PublicAccessBlock", dict))
    if all(bucket.values()):
        return result(False, effective_settings=bucket, account_dependency="not needed for proven true OR operands")
    scope = get(index, "context.scope", str)
    account = scope.split("/")[0]
    if len(account) != 12 or not account.isdigit():
        raise Unavailable("verified AWS scope unavailable")
    if item.get("AccountId") not in (None, account):
        raise Unavailable("conflicting bucket account identity")
    rows = complete_items(index, "s3_account_public_access_block", scope)
    if len(rows) > 1:
        raise Unavailable("ambiguous account public-block inventory")
    account_values = block_settings(rows[0]) if rows else {field: False for field in BLOCKS}
    effective = {field: bucket[field] or account_values[field] for field in BLOCKS}
    return result(not all(effective.values()), effective_settings=effective, semantics="Declared preventive controls, no public endpoint probe or effective access claim")
BUCKET_BLOCK = {field: field in {"BlockPublicAcls", "IgnorePublicAcls"} for field in BLOCKS}
ACCOUNT_GOOD = {"PublicAccessBlockConfiguration": {field: not BUCKET_BLOCK[field] for field in BLOCKS}}
ACCOUNT_BAD = {"PublicAccessBlockConfiguration": {field: False for field in BLOCKS}}
CONTEXT = {"scope": "123456789012/us-east-1"}
CASES["aws.a.s3.bucket_account_public_blocks"] = {"pass": {"PublicAccessBlock": {"PublicAccessBlockConfiguration": BUCKET_BLOCK}},
    "fail": {"PublicAccessBlock": {"PublicAccessBlockConfiguration": BUCKET_BLOCK}}, "missing": {}, "malformed": None,
    "index": {**scope_fixture("s3_account_public_access_block", [ACCOUNT_GOOD]), "context": CONTEXT},
    "fail_index": {**scope_fixture("s3_account_public_access_block", [ACCOUNT_BAD]), "context": CONTEXT}}
NATIVE_IDS.append("aws.a.s3.bucket_account_public_blocks")
