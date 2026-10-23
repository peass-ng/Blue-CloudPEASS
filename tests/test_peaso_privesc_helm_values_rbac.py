"""The documented Helm lab is a bounded, reviewed self-permission gain."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import crole, crb, k8s_snap, sa


ENTRY = yaml.safe_load((Path(__file__).parents[1] / "peaso/privesc/catalog/k8s/helm_values_rbac.yaml").read_text())[0]
SOURCE = "k8s:c1:sa:krte-sc-tenant:tenant-user"
TARGET = f"k8s:verified-authority:c1:krte-sc-prod:secrets:get,list:{SOURCE}"


def proof():
    return {
        "TechniqueId": ENTRY["id"], "Status": "verified", "SourceId": SOURCE,
        "SourceConfigMapNamespace": "krte-sc-source", "SourceConfigMapName": "prod-values",
        "SourceConfigMapKey": "values.json", "ChartRuleField": "rbac.extraRules",
        "ChartSubjectField": "serviceAccount", "ReconcilerNamespace": "applier",
        "ReconcilerServiceAccount": "helm-applier", "ReconcilerCanApplyRole": True,
        "ValuesConsumedByReconciler": True,
        "ReconcilerCanApplyRoleBinding": True, "RenderedRoleNamespace": "krte-sc-prod",
        "RenderedRoleName": "secret-reader", "RenderedRoleBindingName": "tenant-secret-reader",
        "RenderedRoleBindingRoleRef": "Role/krte-sc-prod/secret-reader",
        "RenderedRoleBindingSubject": SOURCE, "BoundSubjectKind": "ServiceAccount",
        "BoundSubjectNamespace": "krte-sc-tenant", "BoundSubjectName": "tenant-user",
        "GrantedResource": "secrets", "GrantedApiGroup": "", "GrantedNamespace": "krte-sc-prod",
        "GrantedVerbs": ["get", "list"], "PriorPermissionAbsent": True,
        "AdmissionAccepted": True, "ReconcileSucceeded": True, "AfterPermissionAllowed": True,
        "EvidenceRef": "reviewed-krte-helm-lab-1",
    }


def case(records=None, *, patch=True, collection_status="collected"):
    rule = {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["prod-values"],
            "verbs": ["patch"] if patch else ["get"]}
    snap = k8s_snap(
        clusterroles=[crole("source-cm", [rule])],
        crbs=[crb("source-cm-binding", "source-cm",
                  {"kind": "ServiceAccount", "name": "tenant-user", "namespace": "krte-sc-tenant"})],
        sas=[sa("tenant-user", "krte-sc-tenant")],
        namespaces=["krte-sc-source", "krte-sc-tenant", "krte-sc-prod"],
        extra=[("k8s_helm_values_rbac_evidence", "c1", [proof()] if records is None else records, collection_status)],
    )
    return snap


def test_reviewed_helm_path_grants_only_exact_extra_permission():
    assert validate_entry(ENTRY)[0] == []
    snap = case()
    before = copy.deepcopy(snap)
    result = privesc.analyze(snap, entries=[ENTRY])
    assert reached(result, SOURCE, ENTRY["id"]) == {TARGET: "conditional"}
    assert snap == before
    assert not any(node["type"] in ("k8s_cluster_admin", "k8s_service_account")
                   and node["id"] != SOURCE for node in result["graph"]["nodes"])
    assert result["graph"]["edges"][0]["technique_details"][0]["grants"] == ENTRY["target"]["grants"]


@pytest.mark.parametrize("field,value", [
    ("SourceId", "k8s:c1:sa:krte-sc-tenant:someone-else"),
    ("SourceConfigMapName", "another-values"),
    ("ChartRuleField", "unused"),
    ("ValuesConsumedByReconciler", False),
    ("ReconcilerCanApplyRoleBinding", False),
    ("RenderedRoleNamespace", "other"),
    ("RenderedRoleBindingSubject", "k8s:c1:sa:krte-sc-tenant:someone-else"),
    ("RenderedRoleBindingRoleRef", "Role/krte-sc-prod/other"),
    ("BoundSubjectName", "someone-else"),
    ("GrantedResource", "pods"),
    ("GrantedVerbs", ["get", "list", "delete"]),
    ("PriorPermissionAbsent", False),
    ("AdmissionAccepted", False),
    ("ReconcileSucceeded", False),
    ("AfterPermissionAllowed", False),
    ("EvidenceRef", ""),
    ("Status", "unreviewed"),
])
def test_mismatched_or_incomplete_review_never_produces_path(field, value):
    record = proof()
    record[field] = value
    assert reached(privesc.analyze(case([record]), entries=[ENTRY]), SOURCE, ENTRY["id"]) == {}


def test_missing_duplicate_partial_or_unpermitted_source_has_no_path():
    for snap in (case([]), case([proof(), proof()]), case(collection_status="partial"), case(patch=False)):
        assert reached(privesc.analyze(snap, entries=[ENTRY]), SOURCE, ENTRY["id"]) == {}


@pytest.mark.parametrize("field", sorted(proof()))
def test_every_review_field_is_required(field):
    record = proof()
    record.pop(field)
    assert reached(privesc.analyze(case([record]), entries=[ENTRY]), SOURCE, ENTRY["id"]) == {}


def test_generic_challenge_selector_cannot_substitute_for_typed_helm_proof():
    invalid = copy.deepcopy(ENTRY)
    invalid["target"]["selector"] = {"k8s_challenge_fact": ENTRY["id"]}
    errors, _ = validate_entry(invalid)
    assert any("k8s_verified_authority needs typed role-binding, Helm, or verified-pivot evidence" in error
               for error in errors)
