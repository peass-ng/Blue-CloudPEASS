"""Scoped credential proofs cannot become unrestricted cloud or cluster admin."""
import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.effective_permissions.credential_evidence import ARGOCD_CONDITIONS, ARGOCD_MOUNT
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import crole, rb, secret, user, k8s_snap, DEV
from tests.test_peaso_privesc_schema_ext_azure import az, SUB, ROLE_ID

ENTRY = yaml.safe_load(Path(__file__).with_name("fixtures").joinpath("privesc_scoped/k8s.yaml").read_text())[0]
TARGET = "k8s_remote_cluster:c1/argocd/production"
AZURE_ENTRIES = yaml.safe_load(Path(__file__).with_name("fixtures").joinpath("privesc_scoped/azure.yaml").read_text())
STORAGE_ACCOUNT = SUB + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storage"
LOCAL_USER = STORAGE_ACCOUNT + "/localUsers/deployer"
CONTAINER = STORAGE_ACCOUNT + "/blobServices/default/containers/delivery"


def storage_case(entry):
    actions = [req["action"] for req in entry["requires"]["all_of"]]
    parent = {"id": STORAGE_ACCOUNT, "name": "storage", "type": "Microsoft.Storage/storageAccounts",
              "properties": {"isSftpEnabled": True, "isLocalUserEnabled": True}}
    local = {"id": LOCAL_USER, "name": "deployer", "properties": {"hasSshPassword": True,
             "allowAclAuthorization": False, "permissionScopes": [{"service": "blob", "resourceName": "delivery", "permissions": "rl"}]}}
    snap = az(assignments=[("u-alice", "User", LOCAL_USER, ROLE_ID)], roles={ROLE_ID: (actions, [])}, extra=[
        ("storage_account", SUB, [parent]), ("storage_local_user", SUB, [local]),
        ("storage_container", SUB, [{"id": CONTAINER}])])
    return snap, parent, local


@pytest.mark.parametrize("entry", AZURE_ENTRIES, ids=lambda e: e["id"])
def test_storage_local_identity_has_only_observed_container_rights(entry):
    assert validate_entry(entry)[0] == []
    snap, _, _ = storage_case(entry)
    before = copy.deepcopy(snap)
    result = privesc.analyze(snap, entries=[entry])
    assert reached(result, "u-alice", entry["id"]) == {"azure_storage_local_user:" + LOCAL_USER.lower(): "conditional"}
    assert snap == before
    assert not any(node["type"] in ("azure_scope_owner", "azure_user", "azure_service_principal")
                   and node["id"] != "u-alice" for node in result["graph"]["nodes"])
    assert not any(edge["source"].startswith("azure_storage_local_user:") for edge in result["graph"]["edges"])
    assert all(finding["status"] != "FAIL" for finding in result["findings"])


@pytest.mark.parametrize("entry", AZURE_ENTRIES, ids=lambda e: e["id"])
@pytest.mark.parametrize("mode", ["sftp_disabled", "local_disabled", "sftp_missing", "local_missing", "parent_partial",
    "user_denied", "user_empty", "parent_empty", "container_empty", "user_duplicate", "parent_duplicate", "user_foreign", "parent_foreign", "container_missing",
    "container_foreign", "container_partial", "parent_scope_empty", "user_scope_empty", "container_scope_empty",
    "scopes_missing", "scopes_malformed", "permission_unknown", "container_wildcard",
    "acl_only", "wrong_resource_permission", "wrong_action", "deny"])
def test_storage_local_identity_rejects_incomplete_or_cross_resource_authority(entry, mode):
    snap, parent, local = storage_case(entry)
    cols = {c["type"]: c for c in snap["collections"]}
    if mode == "sftp_disabled": parent["properties"]["isSftpEnabled"] = False
    elif mode == "local_disabled": parent["properties"]["isLocalUserEnabled"] = False
    elif mode == "sftp_missing": parent["properties"].pop("isSftpEnabled")
    elif mode == "local_missing": parent["properties"].pop("isLocalUserEnabled")
    elif mode == "parent_partial": cols["storage_account"]["status"] = "partial"
    elif mode == "user_denied": cols["storage_local_user"]["status"] = "denied"
    elif mode == "user_empty": cols["storage_local_user"]["status"] = "empty"
    elif mode == "parent_empty": cols["storage_account"]["status"] = "empty"
    elif mode == "container_empty": cols["storage_container"]["status"] = "empty"
    elif mode == "user_duplicate": cols["storage_local_user"]["items"] *= 2
    elif mode == "parent_duplicate": cols["storage_account"]["items"] *= 2
    elif mode == "user_foreign": local["id"] = LOCAL_USER.replace("/storageAccounts/storage/", "/storageAccounts/foreign/")
    elif mode == "parent_foreign": parent["id"] = STORAGE_ACCOUNT + "foreign"
    elif mode == "container_missing": cols["storage_container"]["items"] = []
    elif mode == "container_foreign": cols["storage_container"]["items"][0]["id"] = CONTAINER + "foreign"
    elif mode == "container_partial": cols["storage_container"]["status"] = "partial"
    elif mode == "parent_scope_empty": cols["storage_account"]["scope"] = ""
    elif mode == "user_scope_empty": cols["storage_local_user"]["scope"] = ""
    elif mode == "container_scope_empty": cols["storage_container"]["scope"] = ""
    elif mode == "scopes_missing": local["properties"].pop("permissionScopes")
    elif mode == "scopes_malformed": local["properties"]["permissionScopes"] = [None]
    elif mode == "permission_unknown": local["properties"]["permissionScopes"][0]["permissions"] = "unknown"
    elif mode == "container_wildcard": local["properties"]["permissionScopes"][0]["resourceName"] = "*"
    elif mode == "acl_only": local["properties"].update(permissionScopes=[], allowAclAuthorization=True)
    elif mode == "wrong_resource_permission": cols["role_assignment"]["items"][0]["properties"]["scope"] = LOCAL_USER + "foreign"
    elif mode == "wrong_action": cols["role_definition"]["items"][0]["properties"]["permissions"][0]["actions"] = ["Microsoft.Storage/storageAccounts/read"]
    elif mode == "deny":
        cols["deny_assignment"]["status"] = "collected"
        cols["deny_assignment"]["items"] = [{"id": "denied", "properties": {"scope": LOCAL_USER,
            "principals": [{"id": "u-alice", "type": "User"}],
            "permissions": [{"actions": ["Microsoft.Storage/storageAccounts/localUsers/*"]}]}}]
    result = reached(privesc.analyze(snap, entries=[entry]), "u-alice", entry["id"])
    assert "conditional" not in result.values(), (mode, result)


def test_storage_password_reset_needs_password_auth_but_write_can_add_ssh_key():
    for entry in AZURE_ENTRIES:
        snap, _, local = storage_case(entry)
        local["properties"]["hasSshPassword"] = False
        result = reached(privesc.analyze(snap, entries=[entry]), "u-alice", entry["id"])
        if entry["target"]["selector"]["azure_storage_local_credential"] == "reset_password":
            assert not result
        else:
            assert set(result.values()) == {"conditional"}


def test_all_scoped_paths_are_published_exactly_and_separately_from_historical_bindings():
    from peaso.privesc.effective_permissions.credential_evidence import SCOPED_IDS
    from peaso.privesc.versioned_catalog import current_binding, lookup_entries, BOUNDED_MANIFEST, BOUNDED_TREE, _verified_prior
    current = {e["id"]: {k: v for k, v in e.items() if k != "_file"} for e in privesc.load_catalog()["entries"]}
    prior, _ = _verified_prior()
    assert SCOPED_IDS == {e["id"] for e in [ENTRY, *AZURE_ENTRIES]}
    assert all({k: v for k, v in prior[e["id"]].items() if k != "_file"} == e
               for e in [ENTRY, *AZURE_ENTRIES])
    assert all({k: v for k, v in current[e["id"]].items() if k != "source_revision"} ==
               {k: v for k, v in e.items() if k != "source_revision"}
               for e in [ENTRY, *AZURE_ENTRIES])
    binding = current_binding()
    records, status = lookup_entries(SCOPED_IDS, binding)
    assert status == "exact_strict_privesc" and set(records) == SCOPED_IDS
    old = dict(binding, manifest_sha256=BOUNDED_MANIFEST, effective_tree_sha256=BOUNDED_TREE)
    assert lookup_entries(SCOPED_IDS, old) == ({}, "exact_bounded_v5")


def argocd_case(resource="pods", group=""):
    credential = secret("production", "argocd", labels={"argocd.argoproj.io/secret-type": "cluster"})
    credential["metadata"]["uid"] = "secret-uid-001"
    credential["metadata"]["resourceVersion"] = "103"
    role = crole("author", [{"apiGroups": [group], "resources": [resource], "verbs": ["create"]}])
    snap = k8s_snap(clusterroles=[role], rbs=[rb("author", "argocd", "author", user("dev"))],
                    namespaces=("argocd", "other"), secrets=[credential])
    snap["created_at"] = "2026-10-14T19:00:00Z"
    fact = {"TechniqueId": ARGOCD_MOUNT, "SourceId": DEV, "TargetKind": "k8s_remote_cluster",
            "TargetId": TARGET, "TargetScope": "c1", "Status": "verified", "VerifiedPreconditions": True,
            "EvidenceRef": "reviewed-lab-proof-001", "CredentialUsable": True, "RevocationChecked": True,
            "CredentialKind": "k8s_bearer_token", "CredentialSubjectId": "system:serviceaccount:delivery:deployer",
            "CredentialScope": "remote-production", "CredentialAudience": "https://production.example.invalid:6443",
            "RemoteAcceptedAudience": "https://production.example.invalid:6443",
            "RemoteClusterId": "remote-production", "RemoteServer": "https://production.example.invalid:6443",
            "RemoteAuthorizationVerified": True, "EffectiveRights": ["get:pods:delivery"],
            "EvidenceObservedAt": "2026-10-14T18:59:00Z", "CredentialExpiresAt": "2026-10-14T19:10:00Z",
            "VerifiedConditionIds": list(ARGOCD_CONDITIONS), "SecretName": "production",
            "SecretNamespace": "argocd", "SecretUID": "secret-uid-001", "SecretResourceVersion": "103", "WorkloadNamespace": "argocd",
            "WorkloadResource": resource, "WorkloadApiGroup": group,
            "WorkloadAdmitted": True, "SecretMountVerified": True}
    snap["collections"].append({"type": "k8s_privesc_challenge_evidence", "scope": "c1", "status": "collected",
                                "items": [fact], "error": None, "service": "privesc"})
    return snap, fact


@pytest.mark.parametrize("resource,group", [("pods", ""), ("deployments", "apps"), ("daemonsets", "apps"),
    ("statefulsets", "apps"), ("replicasets", "apps"), ("replicationcontrollers", ""), ("jobs", "batch"), ("cronjobs", "batch")])
def test_argocd_mount_binds_exact_admitted_workload_and_remote_credential(resource, group):
    assert validate_entry(ENTRY)[0] == []
    snap, _ = argocd_case(resource, group)
    before = copy.deepcopy(snap)
    result = privesc.analyze(snap, entries=[ENTRY])
    assert reached(result, DEV, ARGOCD_MOUNT) == {TARGET: "conditional"}
    assert snap == before
    assert all(finding["status"] != "FAIL" for finding in result["findings"])
    nodes = {node["id"]: node for node in result["graph"]["nodes"]}
    assert nodes[TARGET]["kind"] == "principal" and not nodes[TARGET].get("attrs", {}).get("admin")
    assert not any(edge["source"] == TARGET for edge in result["graph"]["edges"])


@pytest.mark.parametrize("change", [
    {"SourceId": DEV + "-other"}, {"TargetId": TARGET + "-other"}, {"TargetScope": "c2"},
    {"SecretUID": "replaced-secret"}, {"SecretResourceVersion": "102"}, {"SecretNamespace": "other"}, {"SecretName": "other"},
    {"WorkloadNamespace": "other"}, {"WorkloadResource": "deployments", "WorkloadApiGroup": "apps"},
    {"WorkloadApiGroup": "wrong"}, {"WorkloadAdmitted": False}, {"SecretMountVerified": False},
    {"CredentialUsable": False}, {"RevocationChecked": False}, {"CredentialKind": "exec_provider"},
    {"CredentialSubjectId": ""}, {"CredentialAudience": "other"}, {"RemoteAcceptedAudience": "other"}, {"CredentialScope": "other"},
    {"RemoteAuthorizationVerified": False}, {"RemoteClusterId": "c1", "CredentialScope": "c1"},
    {"RemoteServer": "http://production.example.invalid"}, {"EffectiveRights": []},
    {"EffectiveRights": ["*"]}, {"EffectiveRights": "get:pods"}, {"EvidenceRef": " "},
    {"VerifiedConditionIds": []}, {"Status": "disproven"}, {"VerifiedPreconditions": False},
    {"CredentialExpiresAt": "2026-10-14T19:00:00Z"}, {"EvidenceObservedAt": "2026-10-14T19:00:01Z"},
    {"EvidenceObservedAt": "2026-10-14T18:44:59Z"}, {"CredentialExpiresAt": "invalid"},
])
def test_argocd_rejects_unbound_expired_or_unverified_evidence(change):
    snap, fact = argocd_case()
    fact.update(change)
    assert "conditional" not in reached(privesc.analyze(snap, entries=[ENTRY]), DEV, ARGOCD_MOUNT).values()


@pytest.mark.parametrize("field", tuple(argocd_case()[1]))
@pytest.mark.parametrize("value", [[], {}])
def test_argocd_malformed_evidence_types_remain_unknown_without_crashing(field, value):
    snap, fact = argocd_case()
    fact[field] = value
    assert "conditional" not in reached(privesc.analyze(snap, entries=[ENTRY]), DEV, ARGOCD_MOUNT).values()


@pytest.mark.parametrize("kind", ["secret_metadata", "k8s_privesc_challenge_evidence"])
@pytest.mark.parametrize("state", ["partial", "denied", "not_collected", "empty"])
def test_argocd_incomplete_inventory_cannot_prove_mount(kind, state):
    snap, _ = argocd_case()
    next(c for c in snap["collections"] if c["type"] == kind)["status"] = state
    assert "conditional" not in reached(privesc.analyze(snap, entries=[ENTRY]), DEV, ARGOCD_MOUNT).values()


@pytest.mark.parametrize("kind", ["secret_metadata", "k8s_privesc_challenge_evidence"])
def test_argocd_duplicate_evidence_and_recreated_secret_are_ambiguous(kind):
    snap, _ = argocd_case()
    next(c for c in snap["collections"] if c["type"] == kind)["items"] *= 2
    assert "conditional" not in reached(privesc.analyze(snap, entries=[ENTRY]), DEV, ARGOCD_MOUNT).values()


@pytest.mark.parametrize("kind", ["secret_metadata", "k8s_privesc_challenge_evidence"])
def test_argocd_duplicate_collection_cannot_hide_a_partial_read(kind):
    snap, _ = argocd_case()
    duplicate = copy.deepcopy(next(c for c in snap["collections"] if c["type"] == kind))
    duplicate.update(status="partial", items=[])
    snap["collections"].insert(0, duplicate)
    assert "conditional" not in reached(privesc.analyze(snap, entries=[ENTRY]), DEV, ARGOCD_MOUNT).values()


def test_kubernetes_token_audience_can_differ_from_api_server_url():
    snap, fact = argocd_case()
    fact["CredentialAudience"] = fact["RemoteAcceptedAudience"] = "https://kubernetes.default.svc.cluster.local"
    assert reached(privesc.analyze(snap, entries=[ENTRY]), DEV, ARGOCD_MOUNT) == {TARGET: "conditional"}


@pytest.mark.parametrize("scope", ["*", "argocd"])
def test_argocd_accepts_native_collector_namespace_or_all_namespace_scopes(scope):
    snap, _ = argocd_case()
    snap["metadata"]["cluster_id"] = "c1"
    next(c for c in snap["collections"] if c["type"] == "secret_metadata")["scope"] = scope
    assert reached(privesc.analyze(snap, entries=[ENTRY]), DEV, ARGOCD_MOUNT) == {TARGET: "conditional"}
    snap["metadata"]["cluster_id"] = "other-cluster"
    assert "conditional" not in reached(privesc.analyze(snap, entries=[ENTRY]), DEV, ARGOCD_MOUNT).values()


def test_argocd_pod_creation_elsewhere_or_resource_names_do_not_mount_secret():
    for mode in ("other_namespace", "resource_names", "missing_fact", "unlabelled_secret"):
        snap, _ = argocd_case()
        if mode == "other_namespace":
            next(c for c in snap["collections"] if c["type"] == "rolebinding")["items"][0]["metadata"]["namespace"] = "other"
        elif mode == "resource_names":
            next(c for c in snap["collections"] if c["type"] == "clusterrole")["items"][0]["rules"][0]["resourceNames"] = ["named-pod"]
        elif mode == "missing_fact":
            snap["collections"] = [c for c in snap["collections"] if c["type"] != "k8s_privesc_challenge_evidence"]
        else:
            next(c for c in snap["collections"] if c["type"] == "secret_metadata")["items"][0]["metadata"]["labels"] = {}
        assert not reached(privesc.analyze(snap, entries=[ENTRY]), DEV, ARGOCD_MOUNT), mode


def test_local_cluster_admin_does_not_imply_remote_cluster_admin():
    from tests.test_peaso_privesc_schema_ext_k8s import crb
    snap, _ = argocd_case()
    columns = {c["type"]: c for c in snap["collections"]}
    columns["clusterrole"]["items"][0]["rules"] = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
    columns["rolebinding"]["items"] = []
    columns["clusterrolebinding"]["items"] = [crb("admin", "author", user("dev"))]
    result = privesc.analyze(snap, entries=[ENTRY])
    assert result["stats"]["admin_principals"] == 1
    assert reached(result, DEV, ARGOCD_MOUNT) == {TARGET: "conditional"}
