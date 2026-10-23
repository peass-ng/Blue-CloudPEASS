"""A DICOM policy write can add new read access only on an exact existing store."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
DATASET = PROJECT + "/locations/us-central1/datasets/clinical"
STORE = DATASET + "/dicomStores/images"
SOURCE = "user:operator@example.com"
WRITER = PROJECT + "/roles/dicomPolicyWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-healthcare-dicomstores-setiampolicy-dicom-store-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": WRITER, "includedPermissions": [
            "healthcare.dicomStores.setIamPolicy"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": WRITER, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("healthcare_dataset", [{"name": DATASET, "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
        envelope("healthcare_dicom_store", [{"name": STORE, "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_store_writer_can_gain_dicomweb_read_on_exact_store():
    got = reached(case())
    assert len(got) == 1 and STORE in got[0][0] and got[0][1] == "conditional"


def test_missing_store_writer_or_new_permission_is_not_a_path():
    snap = case(); snap["collections"][-1] = envelope("healthcare_dicom_store", [])
    assert reached(snap) == []
    snap = case(); snap["collections"][1]["items"][0]["includedPermissions"] = []
    assert reached(snap) == []
    for kind in ("healthcare_dataset", "healthcare_dicom_store"):
        snap = case()
        next(row for row in snap["collections"] if row["type"] == kind)["items"][0]["iamPolicy"]["bindings"].append(
            {"role": "roles/healthcare.dicomViewer", "members": [SOURCE]})
        assert reached(snap) == []


def test_ambiguous_name_or_missing_parent_policy_is_not_definite():
    snap = case()
    snap["collections"][-1]["items"].append(deepcopy(snap["collections"][-1]["items"][0]))
    assert not any(STORE in target and confidence == "conditional" for target, confidence in reached(snap))
    snap = case()
    snap["collections"][-2]["items"][0]["_coverage"]["iamPolicy"]["status"] = "denied"
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
    snap = case()
    snap["collections"][-1]["items"][0]["name"] = STORE.replace("clinical", "other")
    assert reached(snap) == []


def test_writer_condition_must_match_the_exact_dicom_store():
    snap = case()
    binding = snap["collections"][2]["items"][0]["bindings"][0]
    binding["condition"] = {"expression": 'resource.name == "' + STORE + '"'}
    assert reached(snap)[0][1] == "conditional"
    binding["condition"] = {"expression": 'resource.name == "' +
                            STORE.replace("images", "other") + '"'}
    assert reached(snap) == []
