"""Per-technique exact-source, target, and permission proofs for additive v4 paths."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from peaso import privesc
from peaso.privesc.schema import expand_requires
from peaso.privesc.versioned_catalog import _verified_prior
from peaso.privesc.effective_permissions.bounded_evidence import CONTRACT as BOUNDED
from peaso.privesc.effective_permissions.principal_evidence import CONTRACT as EXACT_PRINCIPAL
from peaso.privesc.effective_permissions.credential_evidence import SCOPED_IDS
from peaso.privesc.effective_permissions.azure_disclosure_effects import CONTRACT as DISCLOSURES
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import ROLE_ID, SUB, az
from tests.test_peaso_privesc_v4_batch import _snapshot as base_snapshot
from tests.test_peaso_privesc_v4_gcp_pod_update_join import _case as pod_case


_HISTORY = json.loads((Path(__file__).resolve().parents[1] /
                       "peaso/privesc/catalog_versions/legacy-0b3633-delta.json").read_text())
_ARCHIVED, _ = _verified_prior()
NEW = tuple({key: value for key, value in entry.items() if key != "_file"}
            for entry in _ARCHIVED.values()
            if entry["id"] not in set(_HISTORY["legacy_ids"]) and entry["id"] not in BOUNDED and entry["id"] not in EXACT_PRINCIPAL and entry["id"] not in SCOPED_IDS and entry["id"] not in DISCLOSURES)
POD_ID = "gcp-container-pods-update-running-ksa"
STANDARD = tuple(entry for entry in NEW if entry["id"] != POD_ID)

_AZURE_CREDENTIAL_RESOURCES = {
    "azure-apim-gateway-config-credential": "Microsoft.ApiManagement/service",
    "azure-appconfig-snapshot-credential": "Microsoft.AppConfiguration/configurationStores",
    "azure-automation-job-output-credential": "Microsoft.Automation/automationAccounts",
    "azure-automation-runbook-source-credential": "Microsoft.Automation/automationAccounts",
    "azure-acr-layer-credential": "Microsoft.ContainerRegistry/registries",
    "azure-storage-blob-content-credential": "Microsoft.Storage/storageAccounts",
}


def _actions(entry):
    """Choose one complete DNF arm; each selected action is required in the fixture."""
    arms = expand_requires(entry.get("requires") or {})
    return [requirement["action"] for requirement in (arms[0] if arms else [])]


def _fixture(entry):
    provider, ident = entry["provider"], entry["id"]
    target_kind = entry["target"]["kind"]
    actions = _actions(entry)
    if provider == "aws":
        snap = base_snapshot(entry)
        source = "arn:aws:iam::111111111111:user/alice"
        target = ("arn:aws:iam::111111111111:user/victim" if target_kind == "aws_user"
                  else "arn:aws:iam::111111111111:role/victim")
        collections = {c["type"]: c for c in snap["collections"]}
        if entry.get("source_kind") == "aws_challenge_foothold":
            source = "aws_challenge_foothold:111111111111:local"
        if target_kind == "aws_user":
            collections["iam_user"]["items"].append({"UserName": "victim", "Arn": target,
                "GroupList": [], "AttachedManagedPolicies": [], "UserPolicyList": [],
                "AccessKeys": {"collection_status": "collected", "items": [{
                    "AccessKeyFingerprint": hashlib.sha256(b"AKIAEXAMPLE12345678").hexdigest(),
                    "Status": "Active"}]}})
            snap["created_at"] = "2026-10-22T12:00:00Z"
        user = collections["iam_user"]["items"][0]
        user["UserPolicyList"] = [{"PolicyName": "proof", "PolicyDocument": {
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions,
                                                    "Resource": "*"}]}}] if actions else []
        fact = collections["aws_privesc_challenge_evidence"]["items"][0]
        fact.update(SourceArn=source, TargetId=target, TargetKind=target_kind,
                    EvidenceRef="reviewed-exact-join")
        if target_kind == "aws_account_admin":
            target = "aws_account_admin:111111111111"
        if "trust_allows_service" in entry["target"].get("selector", {}):
            role = collections["iam_role"]["items"][0]
            role["AssumeRolePolicyDocument"] = {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": entry["target"]["selector"]["trust_allows_service"]},
                 "Action": "sts:AssumeRole"}]}
        if target_kind == "aws_user":
            service, action, resource = {
                "aws-apprunner-plaintext-credential": ("apprunner", "apprunner:DescribeService", "service/s/id"),
                "aws-codebuild-plaintext-env-credential": ("codebuild", "codebuild:BatchGetProjects", "project/proof"),
                "aws-lambda-getconfig-secret-identity": ("lambda", "lambda:GetFunctionConfiguration", "function:f"),
            }[ident]
            fact.update(CredentialSubjectArn=target, CredentialKind="aws_iam_user_access_key",
                        CredentialAccessKeyFingerprint=hashlib.sha256(b"AKIAEXAMPLE12345678").hexdigest(),
                        EvidenceObservedAt="2026-10-22T11:59:00Z",
                        CredentialUsable=True, CredentialResourceArn=f"arn:aws:{service}:us-east-1:111111111111:{resource}",
                        AccessAction=action, CredentialReadSucceeded=True,
                        CredentialAuthenticatedAsSubject=True, SourcePreviouslyDenied=True,
                        TargetAccessAfterAllowed=True, NewEffectiveAction="iam:ListRoles",
                        NewEffectiveResource="*")
        return snap, source, target, fact, collections["aws_privesc_challenge_evidence"]
    if provider == "gcp":
        snap = base_snapshot(entry)
        source = "user:alice@corp.com"
        if entry.get("source_kind") == "gcp_challenge_foothold":
            source = "gcp_challenge_foothold:projects/p1:host"
        target = ("workspaceUser:victim@corp.com" if target_kind == "gcp_workspace_user"
                  else "serviceAccount:victim@p1.iam.gserviceaccount.com")
        collections = {c["type"]: c for c in snap["collections"]}
        collections["iam_policy"]["items"][0]["bindings"] = [
            {"role": "projects/p1/roles/proof", "members": [source]}]
        collections["iam_role"]["items"] = [{"name": "projects/p1/roles/proof",
                                             "includedPermissions": actions}]
        fact = collections["gcp_privesc_challenge_evidence"]["items"][0]
        fact.update(SourceId=source, TargetId=target, TargetKind=target_kind,
                    EvidenceRef="reviewed-exact-join")
        if ident in {"gcp-bigquery-table-row-credential", "gcp-bigtable-row-credential"}:
            parent, permission = (("datasets", "bigquery.tables.getData") if "bigquery" in ident
                                  else ("instances", "bigtable.tables.readRows"))
            fact.update(CredentialSubjectId=target, CredentialKind="gcp_service_account_private_key",
                        CredentialUsable=True,
                        CredentialResource=f"projects/p1/{parent}/d/tables/t",
                        AccessPermission=permission)
        return snap, source, target, fact, collections["gcp_privesc_challenge_evidence"]
    if provider == "azure":
        action_values = [action for action in actions if isinstance(action, str)]
        data = [a for arm in expand_requires(entry.get("requires") or {})[:1]
                for a in arm if a.get("data_action")]
        data_names = {a["action"] for a in data}
        snap = az(assignments=[("u-alice", "User", SUB, ROLE_ID)],
                  roles={ROLE_ID: ([a for a in action_values if a not in data_names],
                                   [a for a in action_values if a in data_names])},
                  sps=("target-sp",))
        source, target = "u-alice", "target-sp"
        if entry.get("source_kind") == "azure_challenge_foothold":
            source = f"azure_challenge_foothold:{SUB}:anonymous"
        if target_kind == "azure_managed_identity":
            target = "target-mi"
            graph = next(c for c in snap["collections"] if c["type"] == "resource_graph")
            graph["items"].append({"id": f"{SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/v",
                "type": "Microsoft.Compute/virtualMachines", "identity": {"principalId": target, "type": "SystemAssigned"}})
            graph["status"] = "collected"
        if target_kind == "azure_user":
            target = "u-victim"
            next(c for c in snap["collections"] if c["type"] == "directory_user")["items"].append(
                {"id": target, "userPrincipalName": "u-victim@t.com", "userType": "Member"})
        fact = {"TechniqueId": ident, "SourceId": source, "TargetKind": target_kind,
                "TargetId": target, "TargetScope": SUB, "Status": "verified",
                "VerifiedPreconditions": True, "EvidenceRef": "reviewed-exact-join"}
        evidence = {"type": "azure_privesc_challenge_evidence", "scope": SUB,
                    "service": "privesc", "status": "collected", "items": [fact], "error": None}
        snap["collections"].append(evidence)
        if ident in _AZURE_CREDENTIAL_RESOURCES:
            resource_type = _AZURE_CREDENTIAL_RESOURCES[ident]
            resource = f"{SUB}/resourceGroups/rg/providers/{resource_type}/r"
            graph = next(c for c in snap["collections"] if c["type"] == "resource_graph")
            graph["items"].append({"id": resource, "type": resource_type, "name": "r"})
            graph["status"] = "collected"
            evidence["scope"] = "/tenants/t"
            fact.update(TargetScope="/tenants/t", CredentialSubjectId=target,
                        CredentialKind="entra_service_principal_client_secret",
                        CredentialScope=resource, AccessAction=actions[-1], CredentialUsable=True)
        return snap, source, target, fact, evidence
    raise AssertionError(provider)


def test_every_new_id_has_an_explicit_proof_disposition():
    current={entry["id"] for entry in privesc.load_catalog()["entries"]}
    assert len(NEW) == 48
    assert len({entry["id"] for entry in NEW}) == 48
    assert len(STANDARD) == 47
    assert sum(entry["id"] == POD_ID for entry in NEW) == 1
    assert len(current.intersection(entry["id"] for entry in NEW)) < len(NEW)


@pytest.mark.parametrize("entry", STANDARD, ids=lambda e: e["id"])
def test_exact_positive_source_target_and_permission_counterexamples(entry):
    snap, source, target, fact, evidence = _fixture(entry)
    ident = entry["id"]
    positive = reached(privesc.analyze(snap, entries=[entry]), source, ident)
    assert positive.get(target) == "conditional", (ident, "positive", positive)
    challenge = any(key.endswith("_challenge_fact") for key in entry["target"].get("selector", {}))
    if challenge:
        for field, wrong in (("SourceArn" if entry["provider"] == "aws" else "SourceId", source + "-wrong"),
                             ("TargetId", fact["TargetId"] + "-wrong")):
            altered = copy.deepcopy(snap)
            item = next(c for c in altered["collections"] if c["type"] == evidence["type"])["items"][0]
            item[field] = wrong
            assert target not in reached(privesc.analyze(altered, entries=[entry]), source, ident), (ident, field)
    elif entry["provider"] == "azure" and ident in _AZURE_CREDENTIAL_RESOURCES:
        for field, wrong in (("SourceId", source + "-wrong"), ("TargetId", target + "-wrong"),
                             ("CredentialSubjectId", target + "-wrong"),
                             ("CredentialScope", fact["CredentialScope"] + "-wrong")):
            altered = copy.deepcopy(snap)
            item = next(c for c in altered["collections"] if c["type"] == evidence["type"])["items"][0]
            item[field] = wrong
            assert target not in reached(privesc.analyze(altered, entries=[entry]), source, ident), (ident, field)
    elif entry["provider"] == "aws" and "trust_allows_service" in entry["target"].get("selector", {}):
        altered = copy.deepcopy(snap)
        role = next(c for c in altered["collections"] if c["type"] == "iam_role")["items"][0]
        role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Service"] = "different.amazonaws.com"
        assert target not in reached(privesc.analyze(altered, entries=[entry]), source, ident), (ident, "wrong trust target")
        bob = "arn:aws:iam::111111111111:user/bob"
        other_source = copy.deepcopy(snap)
        next(c for c in other_source["collections"] if c["type"] == "iam_user")["items"].append(
            {"UserName": "bob", "Arn": bob, "GroupList": [], "AttachedManagedPolicies": [], "UserPolicyList": []})
        assert target not in reached(privesc.analyze(other_source, entries=[entry]), bob, ident), (ident, "wrong source")
    elif entry["provider"] == "aws" and entry["target"]["kind"] == "aws_account_admin":
        # A newly created administrator is scoped to the source account, not an existing IAM principal.
        assert "aws_account_admin:222222222222" not in positive
        altered = copy.deepcopy(snap)
        bob = "arn:aws:iam::111111111111:user/bob"
        next(c for c in altered["collections"] if c["type"] == "iam_user")["items"].append(
            {"UserName": "bob", "Arn": bob, "GroupList": [], "AttachedManagedPolicies": [], "UserPolicyList": []})
        assert target not in reached(privesc.analyze(altered, entries=[entry]), bob, ident), (ident, "wrong source")
    if _actions(entry):
        altered = copy.deepcopy(snap)
        if entry["provider"] == "aws":
            next(c for c in altered["collections"] if c["type"] == "iam_user")["items"][0]["UserPolicyList"] = []
        elif entry["provider"] == "gcp":
            next(c for c in altered["collections"] if c["type"] == "iam_role")["items"][0]["includedPermissions"] = []
        else:
            next(c for c in altered["collections"] if c["type"] == "role_assignment")["items"] = []
        assert target not in reached(privesc.analyze(altered, entries=[entry]), source, ident), (ident, "permission")


def test_pod_update_catalog_entry_binds_exact_running_pod_and_token():
    entry = next(entry for entry in NEW if entry["id"] == POD_ID)
    _, snap, related = pod_case()
    source = "user:alice@x.com"
    target = "k8s:gke_p1_us-a_c1:sa:a:builder"

    def reaches(cloud, kube):
        return reached(privesc.analyze(cloud, entries=[entry], related_snapshots=[kube]), source, POD_ID)

    assert reaches(snap, related) == {target: "conditional"}
    for key, value in (("SourceId", "user:bob@x.com"),
                       ("TargetId", "k8s:other:sa:a:builder"),
                       ("AffectedPodUid", "wrong-pod-uid"),
                       ("PodPatchAccepted", False),
                       ("AdmissionAccepted", False),
                       ("ImageExecuted", False),
                       ("CredentialSubjectId", "k8s:other:sa:a:builder"),
                       ("CredentialUsable", False)):
        altered = copy.deepcopy(snap)
        next(c for c in altered["collections"] if c["type"] == "gcp_privesc_challenge_evidence")["items"][0][key] = value
        assert target not in reaches(altered, related), (POD_ID, key)
    altered = copy.deepcopy(snap)
    next(c for c in altered["collections"] if c["type"] == "iam_role")["items"][0]["includedPermissions"] = []
    assert target not in reaches(altered, related), (POD_ID, "permission")
    wrong_pod = copy.deepcopy(related)
    next(c for c in wrong_pod["collections"] if c["type"] == "pod")["items"][0]["metadata"]["uid"] = "wrong-pod-uid"
    assert target not in reaches(snap, wrong_pod), (POD_ID, "pod inventory")


