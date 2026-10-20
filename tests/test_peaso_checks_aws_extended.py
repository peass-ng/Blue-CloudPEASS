"""Independently specified semantic fixtures for the reviewed AWS extension."""
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, aws_extended
from peaso.checks.fixtures import CASES

REGISTRY = {c.id: c for c in CHECKS if c.id in aws_extended.EXTENDED_IDS}


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_every_extended_check_has_semantic_states_and_is_pure(cid):
    check = REGISTRY[cid]
    cases = CASES[cid]
    for label, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("not_applicable", "NOT_APPLICABLE")):
        if label not in cases:
            continue
        item = copy.deepcopy(cases[label])
        before = copy.deepcopy(item)
        assert check.evaluate(item, {})[0] == expected, (cid, label)
        assert item == before
    assert check.evaluate({**copy.deepcopy(cases["pass"]), "collection_status": "denied"}, {})[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "timeout"}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_nested_denied_detail_cannot_pass_using_present_fields(cid):
    passing = CASES[cid]["pass"]
    def visit(value, path=()):
        if not isinstance(value, dict):
            return
        if path:
            item = copy.deepcopy(passing)
            target = item
            for part in path:
                target = target[part]
            target["collection_status"] = "denied"
            assert REGISTRY[cid].evaluate(item, {})[0] == "UNKNOWN", (cid, path)
        for key, child in value.items():
            if isinstance(child, dict):
                visit(child, path + (key,))
    visit(passing)


def evaluate(cid, item):
    return REGISTRY[cid].evaluate(item, {})[0]


@pytest.mark.parametrize("value,expected", [(0, "FAIL"), (1, "PASS"), (90, "PASS"), (91, "FAIL"), (True, "UNKNOWN"), ("90", "UNKNOWN"), (-1, "UNKNOWN")])
def test_password_age_threshold_and_native_integer_type(value, expected):
    assert evaluate("aws.iam.password_max_age", {"PasswordPolicy": {"MaxPasswordAge": value}}) == expected


@pytest.mark.parametrize("value,expected", [(13, "FAIL"), (14, "PASS"), (20, "PASS"), (True, "UNKNOWN"), ("14", "UNKNOWN")])
def test_password_length_lower_bound_matches_reviewed_predicate(value, expected):
    assert evaluate("aws.iam.password_minimum_length", {"PasswordPolicy": {"MinimumPasswordLength": value}}) == expected


@pytest.mark.parametrize("value,expected", [(0, "FAIL"), (23, "FAIL"), (24, "PASS"), (25, "FAIL"), (False, "UNKNOWN")])
def test_password_reuse_is_exactly_24_per_pinned_source(value, expected):
    assert evaluate("aws.iam.password_reuse_prevention", {"PasswordPolicy": {"PasswordReusePrevention": value}}) == expected


@pytest.mark.parametrize("engine", ["aurora", "aurora-mysql", "aurora-postgresql"])
def test_rds_copy_tags_excludes_aurora_without_guessing_cluster_setting(engine):
    assert evaluate("aws.rds.copy_snapshot_tags", {"Engine": engine}) == "NOT_APPLICABLE"
    assert evaluate("aws.rds.copy_snapshot_tags", {"CopyTagsToSnapshot": True}) == "UNKNOWN"


@pytest.mark.parametrize("mode,drop,expected", [("strictest", "false", "PASS"), ("defensive", "false", "PASS"), ("monitor", "true", "PASS"), ("monitor", "false", "FAIL"), ("new-mode", "true", "UNKNOWN"), ("monitor", "unknown", "UNKNOWN")])
def test_load_balancer_desync_preserves_header_drop_alternative(mode, drop, expected):
    assert evaluate("aws.elbv2.desync_mitigation", aws_extended.desync_fixture(mode, drop)) == expected


def test_load_balancer_attribute_duplicate_malformed_missing_and_denied():
    cid = "aws.elbv2.deletion_protection"
    item = aws_extended.lb_fixture("deletion_protection.enabled", "true")
    item["Attributes"]["Attributes"].append({"Key": "deletion_protection.enabled", "Value": "false"})
    assert evaluate(cid, item) == "UNKNOWN"
    assert evaluate(cid, {"Attributes": {"Attributes": []}}) == "UNKNOWN"
    assert evaluate(cid, {"Attributes": {"Attributes": [{"Key": "deletion_protection.enabled", "Value": True}]}}) == "UNKNOWN"
    assert evaluate(cid, {"Attributes": {"collection_status": "denied", "Attributes": [{"Key": "deletion_protection.enabled", "Value": "true"}]}}) == "UNKNOWN"


@pytest.mark.parametrize("attributes,expected", [
    ({"KmsMasterKeyId": "kms-key"}, "PASS"),
    ({"SqsManagedSseEnabled": "true"}, "PASS"),
    ({"KmsMasterKeyId": "", "SqsManagedSseEnabled": "false"}, "FAIL"),
    ({"SqsManagedSseEnabled": "false"}, "UNKNOWN"),
    ({}, "UNKNOWN"),
    ({"KmsMasterKeyId": [], "SqsManagedSseEnabled": "true"}, "UNKNOWN"),
    ({"KmsMasterKeyId": "", "SqsManagedSseEnabled": True}, "UNKNOWN"),
])
def test_sqs_kms_and_sse_alternatives_require_evidence_before_failure(attributes, expected):
    assert evaluate("aws.sqs.encryption", {"Attributes": {"Attributes": attributes}}) == expected


def test_ecr_absence_denial_and_missing_policy_are_distinct():
    cid = "aws.ecr.lifecycle_policy"
    assert evaluate(cid, {"LifecyclePolicy": {"collection_status": "empty", "absent": True}}) == "FAIL"
    assert evaluate(cid, {"LifecyclePolicy": {"collection_status": "denied"}}) == "UNKNOWN"
    assert evaluate(cid, {"LifecyclePolicy": {}}) == "UNKNOWN"
    assert evaluate(cid, {"LifecyclePolicy": {"lifecyclePolicyText": {"rules": []}}}) == "UNKNOWN"


def test_existing_function_url_auth_and_absence_have_correct_applicability():
    cid = "aws.lambda.function_url_authentication"
    assert evaluate(cid, {"FunctionUrl": {"collection_status": "empty", "absent": True}}) == "NOT_APPLICABLE"
    assert evaluate(cid, {"FunctionUrl": {}}) == "UNKNOWN"
    assert evaluate(cid, {"FunctionUrl": {"AuthType": "unknown"}}) == "UNKNOWN"
    assert evaluate(cid, {"FunctionUrl": {"collection_status": "denied", "AuthType": "NONE"}}) == "UNKNOWN"


def test_config_service_role_gates_on_recording_and_matches_account_partition():
    cid = "aws.config.service_linked_role"
    item = aws_extended.config_fixture("arn:aws-us-gov:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig")
    assert evaluate(cid, item) == "PASS"
    item["AccountId"] = "999999999999"
    assert evaluate(cid, item) == "FAIL"
    item["Status"]["ConfigurationRecordersStatus"][0]["recording"] = False
    assert evaluate(cid, item) == "NOT_APPLICABLE"
    item["Status"] = {"collection_status": "denied"}
    assert evaluate(cid, item) == "UNKNOWN"


def test_kms_manager_state_and_disabled_key_eligibility():
    cid = "aws.kms.no_pending_key_deletion"
    assert evaluate(cid, {"Metadata": {"KeyMetadata": {"KeyManager": "AWS"}}}) == "NOT_APPLICABLE"
    assert evaluate(cid, {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Disabled"}}}) == "NOT_APPLICABLE"
    assert evaluate(cid, {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "PendingDeletion"}}}) == "FAIL"
    assert evaluate(cid, {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "new-state"}}}) == "UNKNOWN"


@pytest.mark.parametrize("version,configs,expected", [
    ("1.27", [], "FAIL"), ("1.27", [{"resources": ["secrets"]}], "PASS"),
    ("1.27", [{"resources": ["configmaps"]}], "FAIL"), ("1.28", None, "PASS"),
    ("1.34", None, "PASS"), ("2.0", None, "PASS"), ("invalid", [], "UNKNOWN"),
])
def test_eks_default_envelope_encryption_from_128_and_old_explicit_config(version, configs, expected):
    cluster = {"version": version}
    if configs is not None:
        cluster["encryptionConfig"] = configs
    assert evaluate("aws.eks.secrets_encryption", {"Cluster": {"cluster": cluster}}) == expected


# This shard retains its original review pin. The later AWS source admission
# advanced Prowler's manifest revision without changing any of these 26
# evaluator digests. Accept only that exact revision/URL substitution; never
# treat an arbitrary current manifest revision as a new review.
_PROWLER_REVIEW_REVISION = "61d2cc55c4539a6b48a3cf9f3729d8f2af300882"
_PROWLER_MANIFEST_REVISION = "7f9eb2cb11ea931f54acccb6e49152358ccf949d"


def _assert_reviewed_source_pin(source, reviewed):
    assert source["repository"] == reviewed["repository"]
    assert source["upstream_evaluator"]["sha256"] == reviewed["evaluator_sha256"]
    if reviewed["repository"] == "prowler-cloud/prowler":
        assert reviewed["revision"] == _PROWLER_REVIEW_REVISION
        assert source["revision"] == _PROWLER_MANIFEST_REVISION
    else:
        assert source["revision"] == reviewed["revision"]
    assert source["upstream_evaluator"]["version"] == source["revision"]
    original_prefix = f'https://github.com/{reviewed["repository"]}/blob/{reviewed["revision"]}/'
    successor_prefix = f'https://github.com/{source["repository"]}/blob/{source["revision"]}/'
    assert reviewed["source"].startswith(original_prefix)
    assert source["source"] == reviewed["source"].replace(original_prefix, successor_prefix, 1)


def test_reviewed_shard_ids_exist_at_exact_pinned_source_and_all_native_ids_have_fixtures():
    root = Path(__file__).resolve().parents[1]
    shard = json.loads((root / "peaso/rulepacks/reviewed_aws.json").read_text())
    manifest = json.loads((root / "peaso/rulepacks/upstream_manifest.json").read_text())
    rows = {row["check_id"]: row for row in manifest["checks"]}
    assert len(REGISTRY) >= 30
    supported_native = set()
    for source_id, review in shard.items():
        assert source_id in rows
        assert rows[source_id]["provider"] == "aws"
        _assert_reviewed_source_pin(rows[source_id], review["reviewed_source"])
        assert review["reason"]
        assert review["official_docs"]
        if review["disposition"] in {"ported", "merged"}:
            for native in review["native_checks"]:
                assert native in REGISTRY
                assert native in CASES
                supported_native.add(native)
        else:
            assert review["native_checks"] == []
    assert len(supported_native) >= 30


@pytest.mark.parametrize("mutation", ["future_revision", "review_repin", "evaluator_hash", "repository", "source_path", "evaluator_version"])
def test_reviewed_revision_bridge_rejects_any_other_source_change(mutation):
    root = Path(__file__).resolve().parents[1]
    shard = json.loads((root / "peaso/rulepacks/reviewed_aws.json").read_text())
    manifest = json.loads((root / "peaso/rulepacks/upstream_manifest.json").read_text())
    cid = "prowler.aws.awslambda_function_inside_vpc"
    source = next(row for row in manifest["checks"] if row["check_id"] == cid)
    reviewed = copy.deepcopy(shard[cid]["reviewed_source"])
    _assert_reviewed_source_pin(source, reviewed)
    if mutation == "future_revision":
        source["revision"] = "0" * 40
    elif mutation == "review_repin":
        reviewed["revision"] = source["revision"]
        reviewed["source"] = source["source"]
    elif mutation == "evaluator_hash":
        source["upstream_evaluator"]["sha256"] = "0" * 64
    elif mutation == "repository":
        source["repository"] = "unreviewed/prowler"
    elif mutation == "source_path":
        source["source"] = source["source"].replace("awslambda_function_inside_vpc.metadata.json", "other.metadata.json")
    else:
        source["upstream_evaluator"]["version"] = "0" * 40
    with pytest.raises(AssertionError):
        _assert_reviewed_source_pin(source, reviewed)


@pytest.mark.parametrize("cid", [cid for cid in REGISTRY if cid.startswith("aws.guardduty.")])
def test_guardduty_features_empty_missing_denied_malformed_and_duplicate(cid):
    feature = CASES[cid]["pass"]["Configuration"]["Features"][0]["Name"]
    assert evaluate(cid, {"Configuration": {"Status": "ENABLED", "Features": []}}) == "FAIL"
    assert evaluate(cid, {"Configuration": {}}) == "UNKNOWN"
    assert evaluate(cid, {"Configuration": {"Status": "ENABLED", "Features": [{"Name": feature, "Status": "unknown"}]}}) == "UNKNOWN"
    assert evaluate(cid, {"Configuration": {"Status": "ENABLED", "Features": [{"Name": feature, "Status": "ENABLED"}, {"Name": feature, "Status": "DISABLED"}]}}) == "UNKNOWN"
    assert evaluate(cid, {"Configuration": {"collection_status": "denied", "Features": [{"Name": feature, "Status": "ENABLED"}]}}) == "UNKNOWN"


def test_merged_reviewed_framework_controls_and_versions_are_conserved():
    from tests.compliance_source_conservation import assert_source_frameworks_conserved
    root = Path(__file__).resolve().parents[1]
    reviews = json.loads((root / "peaso/rulepacks/reviewed_aws.json").read_text())
    manifest = json.loads((root / "peaso/rulepacks/upstream_manifest.json").read_text())
    rows = {r["check_id"]: r for r in manifest["checks"]}
    for source_id, review in reviews.items():
        if review["disposition"] != "ported":
            continue
        source = rows[source_id]
        assert source["disposition"] in {"ported", "merged"}, source_id
        assert set(review["native_checks"]) <= set(source["native_checks"])
        for native in review["native_checks"]:
            assert_source_frameworks_conserved(source, native)
