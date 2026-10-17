"""Guard the active catalog's principal/permission escalation boundary."""

from pathlib import Path
import re

import yaml

from peaso.privesc.schema import load_catalog


POLICY = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog_policy.yaml"

# These paths start from a credential or runtime identity already held by the
# source, rather than an additional cloud API grant. Any new exception needs a
# review of its actual starting capability and target credential.
INTRINSIC_FOOTHOLDS = {
    "azure-entraid-pim-group-eligible-activation",
    "k8s-cloud-eks-irsa",
    "k8s-cloud-eks-pod-identity",
    "k8s-cloud-gke-workload-identity",
    "k8s-cloud-aks-workload-identity",
    "k8s-cloud-node-cloud-identity",
    "k8s-cloud-eks-node-role-to-node",
    "k8s-nodes-node-mint-pod-sa-tokens",
    "k8s-nodes-control-plane-node",
}


def test_active_catalog_has_only_sourced_principal_or_permission_paths():
    policy = yaml.safe_load(POLICY.read_text())
    assert policy["schema_version"] == 1
    assert set(policy["providers"]) == {"aws", "azure", "gcp", "k8s"}
    entries = load_catalog(strict=True)["entries"]
    for provider, definition in policy["providers"].items():
        description = definition["description"].lower()
        assert all(word in description for word in (
            "principal", "permissions", "secret", "application", "database", "device", "newly authorized",
        ))
        prefixes = tuple(definition["source_sections"])
        for entry in (row for row in entries if row["provider"] == provider):
            source = entry["source"]
            assert isinstance(source, str) and "#" in source and source.rsplit("#", 1)[1], entry["id"]
            assert re.fullmatch(r"[0-9a-f]{7,40}", str(entry.get("source_revision", ""))), entry["id"]
            assert source.startswith(prefixes), (entry["id"], source)
            target = entry["target"]
            kind = target["kind"]
            selector = target.get("selector") or {}
            assert kind != "k8s_admission_control", entry["id"]
            if kind == "aws_verified_authority":
                assert target.get("outcome") == "permission_grant", entry["id"]
                reviewed = ("aws_s3_policy_self_grant", "aws_s3_access_grants_self_grant",
                            "aws_secretsmanager_policy_self_grant", "aws_efs_policy_self_grant",
                            "aws_cases_tag_self_grant", "aws_sitewise_portal_self_grant")
                assert sum(bool(selector.get(key)) for key in reviewed) == 1, entry["id"]
            elif kind == "azure_verified_authority":
                assert entry["id"] in {
                    "azure-purview-policy-self-grant",
                    "azure-storage-adls-acl-self-grant",
                    "azure-storage-files-acl-self-grant",
                }, entry["id"]
                assert target.get("outcome") == "permission_grant", entry["id"]
                assert selector.get("azure_challenge_fact") == entry["id"], entry["id"]
            elif kind == "azure_external_principal":
                from peaso.privesc.effective_permissions.azure_external_principal import CONTRACT
                assert entry["id"] in CONTRACT, entry["id"]
                assert selector == {"azure_external_principal_evidence": True,
                                    "azure_external_plane": CONTRACT[entry["id"]][1]}, entry["id"]
                assert target.get("outcome") == (
                    "credentials" if CONTRACT[entry["id"]][2] == "credential" else "identity"), entry["id"]
            if entry["id"] == "azure-datafactory-dataplane-access-token":
                assert kind == "azure_managed_identity", entry["id"]
                assert selector == {"azure_challenge_fact": entry["id"]}, entry["id"]
                assert target.get("outcome") == "credentials", entry["id"]
            elif kind == "gcp_verified_authority":
                if selector.get("gcp_bounded_access_gain") is True:
                    assert target.get("outcome") == "bounded_authority", entry["id"]
                    assert selector.get("gcp_bounded_mechanism") in {
                        "biglake_connection_table", "bigquery_remote_function",
                        "bigquery_authorized_routine", "bigquery_authorized_view",
                        "bigquery_authorized_dataset",
                    }, entry["id"]
                else:
                    assert target.get("outcome") == "permission_grant", entry["id"]
                    assert selector.get("gcp_resource_self_grant") is True, entry["id"]
                assert target.get("grants"), entry["id"]
            requires = entry.get("requires") or {}
            if not (requires.get("all_of") or requires.get("any_of")):
                assert entry["id"] in INTRINSIC_FOOTHOLDS, entry["id"]


def test_intrinsic_foothold_exceptions_are_still_active():
    ids = {row["id"] for row in load_catalog(strict=True)["entries"]}
    assert INTRINSIC_FOOTHOLDS <= ids


def test_scan_does_not_turn_missing_target_inventory_into_a_path(monkeypatch):
    from peaso import engine, privesc
    from tests.test_peaso_privesc_followups import aws_snap, entry, role, trust_service, user

    technique = entry(
        "aws-test-missing-host-join", "aws",
        {"all_of": [{"action": "lambda:UpdateFunctionCode", "resource": "*"}]},
        {"kind": "aws_role", "selector": {"attached_to_service": "lambda"}, "scope": "same_account"},
    )
    snapshot = aws_snap(
        [user("alice", {"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": "*"})],
        [role("app", trust_service("lambda.amazonaws.com"))],
    )
    diagnostic = privesc.analyze(snapshot, entries=[technique], include_unknown=True)
    assert any(edge["target"].startswith("unresolved:") for edge in diagnostic["graph"]["edges"])
    monkeypatch.setattr(privesc, "catalog", lambda: {"entries": [technique]})
    findings, coverage, graph, _, _ = engine._run_privesc(snapshot, {technique["id"]})
    assert not findings and not graph["edges"]
    assert any(row.get("kind") == "selector" for row in coverage)
