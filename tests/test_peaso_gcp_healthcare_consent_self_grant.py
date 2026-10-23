"""Consent-store policy writers need a named store and a usable new read grant."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
DATASET = PROJECT + "/locations/us-central1/datasets/clinical"
STORE = DATASET + "/consentStores/research"
SOURCE = "user:operator@example.com"
WRITER = PROJECT + "/roles/consentPolicyWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-healthcare-consentstores-setiampolicy-consent-store-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": WRITER, "includedPermissions": [
            "healthcare.consentStores.setIamPolicy",
            "healthcare.consentStores.getIamPolicy"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": WRITER, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []),
        envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("healthcare_dataset", [{"name": DATASET, "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
        envelope("healthcare_consent_store", [{"name": STORE, "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
    ]}


def reached(snapshot):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snapshot), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_named_consent_store_policy_writer_has_conditional_new_read_grant():
    result = reached(case())
    assert len(result) == 1 and STORE in result[0][0]
    assert result[0][1] == "conditional"


def test_no_policy_writer_or_existing_reader_is_not_a_new_gain():
    snapshot = case()
    snapshot["collections"][1]["items"][0]["includedPermissions"].remove(
        "healthcare.consentStores.setIamPolicy")
    assert reached(snapshot) == []
    snapshot = case()
    snapshot["collections"][7]["items"][0]["iamPolicy"]["bindings"].append({
        "role": "roles/healthcare.consentReader", "members": [SOURCE]})
    assert reached(snapshot) == []


def test_dataset_reader_and_iam_resource_condition_are_honored():
    snapshot = case()
    snapshot["collections"][7]["items"][0]["iamPolicy"]["bindings"].append({
        "role": "roles/healthcare.consentReader", "members": [SOURCE]})
    assert reached(snapshot) == []
    snapshot = case()
    snapshot["collections"][2]["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + STORE + "'"}
    assert reached(snapshot)[0][1] == "conditional"
    snapshot["collections"][2]["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + DATASET + "'"}
    assert reached(snapshot) == []


def test_missing_policy_or_prior_read_state_remains_unknown():
    snapshot = case()
    snapshot["collections"][8]["items"][0]["_coverage"]["iamPolicy"]["status"] = "denied"
    assert reached(snapshot)[0][1] == "unknown"
    snapshot = case()
    snapshot["collections"][7]["items"][0]["_coverage"]["iamPolicy"]["status"] = "denied"
    assert reached(snapshot)[0][1] == "unknown"
    snapshot = case()
    snapshot["collections"][1]["items"][0]["includedPermissions"].remove(
        "healthcare.consentStores.getIamPolicy")
    assert reached(snapshot)[0][1] == "unknown"


def test_wrong_project_or_duplicate_store_is_not_a_definite_path():
    snapshot = case()
    snapshot["collections"][8]["items"][0]["name"] = STORE.replace(
        "demo-project1", "another-project")
    assert reached(snapshot) == []
    snapshot = case()
    snapshot["collections"][8]["items"].append(deepcopy(
        snapshot["collections"][8]["items"][0]))
    assert reached(snapshot) == []
