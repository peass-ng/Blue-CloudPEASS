"""Dataset IAM self-grants require one real child FHIR store and new access."""
from __future__ import annotations

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
DATASET = PROJECT + "/locations/us-central1/datasets/clinical"
STORE = DATASET + "/fhirStores/patients"
OTHER = DATASET + "/fhirStores/other"
SOURCE = "user:operator@example.com"
WRITER = PROJECT + "/roles/datasetPolicyWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-healthcare-datasets-setiampolicy-dataset-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": WRITER, "includedPermissions": [
            "healthcare.datasets.setIamPolicy"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": WRITER, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("healthcare_dataset", [{"name": DATASET, "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
        envelope("healthcare_fhir_store", [{"name": STORE, "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_dataset_writer_can_gain_search_on_existing_child_store():
    assert (STORE in reached(case())[0][0]
            and reached(case())[0][1] == "conditional")


def test_no_store_no_writer_or_existing_access_does_not_emit_new_gain():
    snap = case(); snap["collections"][-1] = envelope("healthcare_fhir_store", [])
    assert reached(snap) == []
    snap = case(); snap["collections"][1]["items"][0]["includedPermissions"] = []
    assert reached(snap) == []
    for kind in ("healthcare_dataset", "healthcare_fhir_store"):
        snap = case()
        next(row for row in snap["collections"] if row["type"] == kind)["items"][0]["iamPolicy"]["bindings"].append(
            {"role": "roles/healthcare.fhirResourceReader", "members": [SOURCE]})
        assert reached(snap) == []


def test_ambiguous_store_and_incomplete_policies_do_not_become_definite():
    snap = case()
    snap["collections"][-1]["items"].append(deepcopy(snap["collections"][-1]["items"][0]))
    assert not any(STORE in target and confidence == "conditional" for target, confidence in reached(snap))
    snap = case()
    snap["collections"][-1]["items"][0]["_coverage"]["iamPolicy"]["status"] = "denied"
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
    snap = case()
    snap["collections"][-1]["items"][0]["name"] = OTHER
    snap["collections"][-2]["items"][0]["name"] = DATASET.replace("clinical", "unrelated")
    assert reached(snap) == []
