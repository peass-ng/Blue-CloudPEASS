"""Native registry behavior over immutable provider facts, with no credentials."""
import copy
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.fixtures import CASES
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


PAB = {key: True for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
BASE = {
 "aws.iam.no_full_admin": ({"PolicyDocument": {"Statement": []}}, {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}),
 "aws.iam.restrict_public_trust": ({"AssumeRolePolicyDocument": {"Statement": []}}, {"AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}}),
 "aws.iam.console_mfa": ({"LoginProfile": {"LoginProfile": {"UserName": "alice"}}, "MFADevices": {"collection_status": "collected", "items": [{"SerialNumber": "mfa"}]}}, {"LoginProfile": {"LoginProfile": {"UserName": "alice"}}, "MFADevices": {"collection_status": "empty", "items": []}}),
 "aws.s3.public_access_block": ({"PublicAccessBlock": {"PublicAccessBlockConfiguration": PAB}}, {"PublicAccessBlock": {"PublicAccessBlockConfiguration": {**PAB, "IgnorePublicAcls": False}}}),
 "aws.ec2.restrict_internet_ingress": ({"IpPermissions": []}, {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}),
 "aws.ec2.imdsv2": ({"MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}}, {"MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"}}),
 "gcp.iam.restrict_public_members": ({"bindings": []}, {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}),
 "gcp.iam.avoid_basic_roles": ({"bindings": []}, {"bindings": [{"role": "roles/editor", "members": ["user:a@example.com"]}]}),
 "gcp.storage.uniform_access": ({"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}, {"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}}}),
 "gcp.compute.restrict_internet_ingress": ({"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "sourceRanges": ["10.0.0.0/8"]}, {"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "sourceRanges": ["0.0.0.0/0"]}),
 "gcp.compute.no_external_ip": ({"networkInterfaces": []}, {"networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.1"}]}]}),
 "azure.storage.https_only": ({"properties": {"supportsHttpsTrafficOnly": True}}, {"properties": {"supportsHttpsTrafficOnly": False}}),
 "azure.storage.no_blob_public_access": ({"properties": {"allowBlobPublicAccess": False}}, {"properties": {"allowBlobPublicAccess": True}}),
 "azure.storage.minimum_tls": ({"properties": {"minimumTlsVersion": "TLS1_2"}}, {"properties": {"minimumTlsVersion": "TLS1_0"}}),
 "azure.iam.review_owner_assignment": ({"properties": {"roleDefinitionId": "/roles/reader", "principalId": "alice"}}, {"properties": {"roleDefinitionId": "/roles/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "principalId": "alice"}}),
 "azure.iam.no_full_custom_role": ({"properties": {"type": "CustomRole", "permissions": [{"actions": ["Microsoft.Storage/storageAccounts/read"]}]}}, {"properties": {"type": "CustomRole", "permissions": [{"actions": ["*"]}]}}),
 "azure.network.restrict_internet_ingress": ({"properties": {"securityRules": []}}, {"properties": {"securityRules": [{"properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "Internet", "destinationPortRange": "22", "protocol": "Tcp"}}]}}),
 "k8s.rbac.role_no_wildcards": ({"rules": []}, {"rules": [{"verbs": ["*"], "resources": ["pods"], "apiGroups": [""]}]}),
 "k8s.rbac.no_wildcards": ({"rules": []}, {"rules": [{"verbs": ["*"], "resources": ["pods"], "apiGroups": [""]}]}),
 "k8s.rbac.review_namespaced_subjects": ({"roleRef": {"kind": "Role", "name": "view"}, "subjects": []}, {"roleRef": {"kind": "Role", "name": "view"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}]}),
 "k8s.rbac.review_broad_subjects": ({"roleRef": {"kind": "ClusterRole", "name": "view"}, "subjects": []}, {"roleRef": {"kind": "ClusterRole", "name": "view"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}]}),
 "k8s.pod.no_privileged_containers": ({"spec": {"containers": [{"name": "app", "securityContext": {"privileged": False}}]}}, {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}}),
 "k8s.pod.no_host_namespaces": ({"spec": {"hostPID": False}}, {"spec": {"hostPID": True}}),
 "k8s.service.review_public_type": ({"spec": {"type": "ClusterIP"}}, {"spec": {"type": "LoadBalancer"}}),
}
for cid, (passing, failing) in BASE.items():
    CASES[cid] = {"pass": passing, "fail": failing}
CASES["aws.s3.default_encryption"] = {"pass": {"Encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}}, "unknown": {"Encryption": {"absent": True}}}
CASES["gcp.storage.public_access_prevention"] = {"pass": {"iamConfiguration": {"publicAccessPrevention": "enforced"}}, "unknown": {"iamConfiguration": {"publicAccessPrevention": "inherited"}}}
CASES["k8s.network.namespace_policy_inventory"] = {"manual": {"metadata": {"name": "apps"}}, "fail": {"metadata": {"name": "empty"}}, "index": {"collections": {"networkpolicy": [{"scope": "apps", "status": "collected"}, {"scope": "empty", "status": "empty"}]}, "networkpolicy": [{"data": {"metadata": {"namespace": "apps"}}}]}}


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.id)
def test_every_check_has_behavior_fixtures(check):
    assert check.id in CASES, "registered checks cannot claim support without fixtures"
    cases = CASES[check.id]
    index = cases.get("index", {})
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"), ("manual", "MANUAL"), ("unknown", "UNKNOWN")):
        if name in cases:
            data = copy.deepcopy(cases[name])
            before = copy.deepcopy(data)
            assert check.evaluate(data, copy.deepcopy(index))[0] == expected
            assert data == before, "evaluators must not mutate native snapshot facts"
    assert check.evaluate(cases.get("missing", {}), index)[0] == "UNKNOWN"
    assert check.evaluate(cases.get("malformed", None), index)[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, index)[0] == "UNKNOWN"
    assert HACKTRICKS in check.frameworks


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.id)
@pytest.mark.parametrize("collection_status,expected", [("denied", "DENIED"), ("unknown", "UNKNOWN"), ("malformed", "UNKNOWN"), ("empty", "EMPTY")])
def test_unavailable_inventory_never_passes(check, collection_status, expected):
    snapshot = make_snapshot(check.provider, ["test-scope"], [{"type": check.kind, "scope": "test-scope", "service": "test", "status": collection_status, "items": []}])
    report = evaluate_snapshot(snapshot, categories=[check.category], checks=[check.id])
    assert report["findings"][0]["status"] == expected
    assert "PASS" not in report["stats"]["by_status"]


def test_partial_inventory_carries_resource_evidence_and_unknown_remainder():
    snapshot = make_snapshot("aws", ["us-east-1"], [{"type": "ebs_volume", "scope": "us-east-1", "status": "partial", "service": "ec2", "items": [{"VolumeId": "vol-a", "Encrypted": True}], "error": {"code": "page_limit"}}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ebs.encryption"])
    assert report["stats"]["by_status"] == {"PASS": 1, "UNKNOWN": 1}
    assert report["stats"]["coverage_complete"] is False


def test_nested_denied_and_malformed_are_unknown():
    registry = {c.id: c for c in CHECKS}
    assert registry["aws.iam.console_mfa"].evaluate({"LoginProfile": {"collection_status": "denied"}, "MFADevices": []}, {})[0] == "UNKNOWN"
    assert registry["gcp.storage.no_public_iam"].evaluate({"iamPolicy": {"bindings": []}, "_coverage": {"iamPolicy": {"status": "denied"}}}, {})[0] == "UNKNOWN"
    assert registry["aws.cloudtrail.logging"].evaluate({"Status": {"collection_status": "denied", "IsLogging": False}}, {})[0] == "UNKNOWN"
    assert registry["azure.network.restrict_internet_ingress"].evaluate({"properties": {"securityRules": [{}]}}, {})[0] == "UNKNOWN"
    assert registry["aws.iam.restrict_public_trust"].evaluate({"AssumeRolePolicyDocument": {"Statement": [{"Principal": "*"}]}}, {})[0] == "UNKNOWN"


def test_pod_init_ephemeral_inheritance_and_purity():
    registry = {c.id: c for c in CHECKS}
    data = {"spec": {"securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "app"}], "initContainers": [{"name": "init"}], "ephemeralContainers": [{"name": "debug", "securityContext": {"runAsUser": 0}}]}}
    before = copy.deepcopy(data)
    assert registry["k8s.pod.non_root"].evaluate(data, {}) == ("FAIL", {"containers_needing_review": ["debug"], "semantics": "Native pod configuration; admission policy and runtime enforcement are separate"})
    assert registry["k8s.pod.seccomp"].evaluate(data, {})[0] == "PASS"
    assert data == before


def test_framework_union_evaluates_predicate_once():
    check = next(c for c in CHECKS if c.id == "aws.ebs.encryption")
    tags = check.frameworks
    snapshot = make_snapshot("aws", ["us-east-1"], [{"type": check.kind, "scope": "us-east-1", "service": "ec2", "status": "collected", "items": [{"VolumeId": "vol-a", "Encrypted": True}]}])
    result = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check.id], frameworks=tags)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["frameworks"] == tags


def test_manifest_validator_and_mapping_conservation():
    from scripts.peaso_review_catalog import validate_manifest
    from peaso.checks.catalog import manifest
    data = manifest()
    stats = validate_manifest(data)
    assert stats["upstream_total"] > stats["native_checks"]
    registry = {c.id: c for c in CHECKS}
    for row in data["checks"]:
        if row["disposition"] in ("ported", "merged"):
            for cid in row["native_checks"]:
                mapping = registry[cid].mapping
                for tag in row["frameworks"]:
                    assert any(tag in value.get("controls", []) for value in mapping.values())
        else:
            assert not row["native_checks"]


def test_no_blanket_nist_tags():
    check = next(c for c in CHECKS if c.id == "k8s.namespace.restricted_admission")
    assert check.frameworks == [HACKTRICKS]


def test_framework_catalog_contains_families_and_preserves_control_tree():
    from peaso.engine import get_catalog
    from peaso.checks.catalog import manifest
    names = [f["name"] for f in get_catalog()["frameworks"]]
    assert len(names) < 100
    assert not {"Pod", "Storage", "Account", "Your Data", "All AWS Compliance Controls"}.intersection(names)
    assert not any(name.startswith(("1.2.1.a ", "PR.AC-", "AC-2 ")) for name in names)
    for row in manifest()["checks"]:
        for mapping in row["frameworks"]:
            if row["repository"].startswith("turbot/"):
                assert mapping["framework_id"] in mapping["benchmark_ids"]


def test_current_provider_semantic_exceptions():
    registry = {c.id: c for c in CHECKS}
    assert registry["gcp.gke.network_policy"].evaluate({"networkConfig": {"datapathProvider": "ADVANCED_DATAPATH"}, "networkPolicy": {"enabled": False}}, {})[0] == "PASS"
    assert registry["azure.aks.network_policy"].evaluate({"properties": {"networkProfile": {"networkDataplane": "cilium", "networkPolicy": "none"}}}, {})[0] == "PASS"
    assert registry["azure.storage.minimum_tls"].evaluate({"properties": {"minimumTlsVersion": "TLS1_3"}}, {})[0] == "UNKNOWN"
    assert registry["gcp.storage.public_access_prevention"].evaluate({"iamConfiguration": {"publicAccessPrevention": "unspecified"}}, {})[0] == "UNKNOWN"
    assert registry["aws.iam.root_mfa"].evaluate({"user": "<root_account>", "password_enabled": "false", "access_key_1_active": "false", "access_key_2_active": "false", "mfa_active": "false"}, {})[0] == "NOT_APPLICABLE"
