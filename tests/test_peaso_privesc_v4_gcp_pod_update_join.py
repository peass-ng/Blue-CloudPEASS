"""An image patch reaches only the inventoried running pod's KSA."""

from __future__ import annotations

import copy

import pytest

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_v2 import GCP_ENTRY, gcp_snap, k8s_related


ID = "gcp-container-pods-update-running-ksa"
SOURCE = "user:alice@x.com"
TARGET = "k8s:gke_p1_us-a_c1:sa:a:builder"
CLUSTER = "projects/p1/locations/us-a/clusters/c1"


def _case():
    entry = copy.deepcopy(GCP_ENTRY)
    entry["id"] = ID
    entry["requires"] = {"all_of": [{"action": "container.pods.update", "resource": "{target.scope}"}]}
    entry["target"]["selector"]["gcp_challenge_fact"] = ID
    snap = gcp_snap()
    next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]["includedPermissions"] = ["container.pods.update"]
    fact = {"TechniqueId": ID, "SourceId": SOURCE, "TargetKind": "k8s_service_account",
            "TargetId": TARGET, "TargetScope": "projects/p1", "Status": "verified",
            "VerifiedPreconditions": True, "EvidenceRef": "reviewed-pod-patch",
            "AffectedCluster": CLUSTER, "AffectedPodNamespace": "a", "AffectedPodName": "p",
            "AffectedPodUid": "pod-uid-1", "PodPatchAccepted": True, "AdmissionAccepted": True,
            "ImageExecuted": True, "CredentialSubjectId": TARGET,
            "CredentialKind": "k8s_service_account_token", "CredentialAudience": "kubernetes_api",
            "CredentialUsable": True}
    snap["collections"].append({"type": "gcp_privesc_challenge_evidence", "scope": "projects/p1",
                                "service": "privesc", "status": "collected", "items": [fact], "error": None})
    related = k8s_related()
    next(c for c in related["collections"] if c["type"] == "pod")["items"][0]["metadata"]["uid"] = "pod-uid-1"
    return entry, snap, related


def _reach(entry, snap, related):
    return reached(privesc.analyze(snap, entries=[entry], related_snapshots=[related]), SOURCE, ID)


def test_exact_pod_patch_reaches_only_its_ksa_conditionally():
    entry, snap, related = _case()
    assert _reach(entry, snap, related) == {TARGET: "conditional"}


@pytest.mark.parametrize("field,value", [
    ("SourceId", "user:bob@x.com"), ("TargetId", TARGET + "-other"),
    ("AffectedCluster", "projects/p1/locations/us-a/clusters/other"),
    ("AffectedPodNamespace", "other"), ("AffectedPodName", "other"),
    ("AffectedPodUid", "other"), ("PodPatchAccepted", False),
    ("AdmissionAccepted", False), ("ImageExecuted", False),
    ("CredentialSubjectId", "k8s:other:sa:a:builder"),
    ("CredentialKind", "opaque_string"), ("CredentialAudience", "other"),
    ("CredentialUsable", False), ("EvidenceRef", ""),
])
def test_wrong_fact_does_not_reach_ksa(field, value):
    entry, snap, related = _case()
    snap["collections"][-1]["items"][0][field] = value
    assert TARGET not in _reach(entry, snap, related)


def test_wrong_permission_or_pod_inventory_does_not_reach_ksa():
    entry, snap, related = _case()
    next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]["includedPermissions"] = []
    assert TARGET not in _reach(entry, snap, related)
    entry, snap, related = _case()
    pod = next(c for c in related["collections"] if c["type"] == "pod")["items"][0]
    pod["metadata"]["uid"] = "different-pod"
    assert TARGET not in _reach(entry, snap, related)
    entry, snap, related = _case()
    pod = next(c for c in related["collections"] if c["type"] == "pod")["items"][0]
    pod["status"]["phase"] = "Pending"
    assert TARGET not in _reach(entry, snap, related)


def test_missing_or_conflicting_fact_cannot_claim_ksa():
    entry, snap, related = _case()
    snap["collections"][-1]["items"] = []
    assert TARGET not in _reach(entry, snap, related)
    entry, snap, related = _case()
    snap["collections"][-1]["items"].append(copy.deepcopy(snap["collections"][-1]["items"][0]))
    assert TARGET not in _reach(entry, snap, related)
