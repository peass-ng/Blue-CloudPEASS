"""Truth fixtures for entity applicability, scope joins and literal predicates."""
import copy
import pytest
from peaso.checks import CHECKS, gcp_ports_iam as ports
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_metadata_truths(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    index = copy.deepcopy(CASES[cid].get("index", {}))
    before = copy.deepcopy((item, index))
    status, evidence = REGISTRY[cid].evaluate(item, index)
    assert status == wanted, evidence
    assert (item, index) == before




def test_kms_duty_conditions_remain_declarations_not_simultaneous_access():
    cid = ports.REFERENCE_SPECS["kms_key_separation_of_duties_enforced"]
    item = copy.deepcopy(CASES[cid]["fail"])
    item["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2026-01-01T00:00:00Z')"}
    item["bindings"][1]["condition"] = {"expression": "request.time >= timestamp('2026-01-01T00:00:00Z')"}
    status, evidence = REGISTRY[cid].evaluate(item, {})
    assert status == "FAIL"
    assert all(row["condition"] for row in evidence["overlapping_role_declarations"][0]["declarations"])
    assert "does not assert simultaneous" in evidence["semantics"]


def test_source_crossproject_duty_join_false_alarm_and_native_root_scope():
    cid = ports.REFERENCE_SPECS["iam_user_separation_of_duty_scoped"]
    user = "user:a@example.com"
    admin_project = {"name": "projects/p", "bindings": [{"role": "roles/iam.serviceAccountAdmin", "members": [user]}]}
    use_project = {"name": "projects/q", "bindings": [{"role": "roles/iam.serviceAccountUser", "members": [user]}]}
    # SQL's global user_name IN both CTEs alarms although no project grants both.
    assert user in admin_project["bindings"][0]["members"] and user in use_project["bindings"][0]["members"]
    assert REGISTRY[cid].evaluate(admin_project, {})[0] == "PASS"
    assert REGISTRY[cid].evaluate(use_project, {})[0] == "PASS"
    assert REGISTRY[cid].evaluate({"name": "organizations/o", "bindings": []}, {})[0] == "NOT_APPLICABLE"


def test_source_role_suffix_cannot_classify_actual_permission_metadata():
    cid = ports.REFERENCE_SPECS["service_account_mutating_role_declarations"]
    fixture = CASES[cid]
    reader_role, writer_role = [row["data"] for row in fixture["index"]["iam_role"]]
    assert reader_role["name"].endswith("Admin") and not writer_role["name"].endswith(("admin", "Admin", "Editor", "Owner", "editor", "owner"))
    assert REGISTRY[cid].evaluate(fixture["pass"], fixture["index"])[0] == "PASS"
    assert REGISTRY[cid].evaluate(fixture["fail"], fixture["index"])[0] == "FAIL"


def test_source_primary_domain_rejects_valid_secondary_domain_policy():
    cid = ports.REFERENCE_SPECS["iam_corporate_domain_declaration"]
    fixture = CASES[cid]
    user = fixture["pass"]["bindings"][0]["members"][0]
    assert user.split("@")[1] != "primary.example"  # SQL's organization.display_name primary domain join fails.
    assert REGISTRY[cid].evaluate(fixture["pass"], fixture["index"])[0] == "PASS"
    assert REGISTRY[cid].evaluate(fixture["pass"], {})[0] == "UNKNOWN"
    assert REGISTRY[cid].evaluate(fixture["pass"], {"context": {"metadata": {"trusted_domains": [], "trusted_domains_explicit": False}}})[0] == "UNKNOWN"


@pytest.mark.parametrize("query", ["function_basic_role_declarations", "function_logging_mutation_declarations", "function_legacy_deployment_role_declarations"])
def test_function_source_presence_is_not_permission_assignment(query):
    cid = ports.REFERENCE_SPECS[query]
    fixture = CASES[cid]
    # All three SQL CASEs test f.service_account_email, never the joined policy row.
    assert fixture["pass"]["serviceConfig"]["serviceAccountEmail"]
    assert REGISTRY[cid].evaluate(fixture["pass"], fixture["index"])[0] == "PASS"


def test_missing_and_denied_ancestor_policy_cannot_clean_role_declaration_review():
    cid = ports.REFERENCE_SPECS["service_account_mutating_role_declarations"]
    fixture = CASES[cid]
    index = copy.deepcopy(fixture["index"])
    index["project"][0]["data"]["_ancestry"] = [{"resourceId": {"type": "folder", "id": "f"}}]
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"
    index["iam_policy"].append({"data": {"name": "folders/f", "bindings": []}})
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "PASS"
    index["collections"]["iam_policy"].append({"status": "denied", "scope": "folders/f"})
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"


def test_duplicate_role_reads_are_equivalent_only_with_exact_owner_permissions_and_version():
    cid = ports.REFERENCE_SPECS["service_account_mutating_role_declarations"]
    fixture = CASES[cid]
    index = copy.deepcopy(fixture["index"])
    original = copy.deepcopy(index["iam_role"][0])
    index["iam_role"].append(original)
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "PASS"
    original["data"]["includedPermissions"] = ["storage.buckets.update"]
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"
    original["data"]["name"] = "projects/unrelated/roles/harmlessAdmin"
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "PASS"


def test_mutating_role_declarations_use_materialized_ancestor_root_policies():
    cid = ports.REFERENCE_SPECS["service_account_mutating_role_declarations"]
    ancestry = [{"resourceId": {"type": "project", "id": "p"}}, {"resourceId": {"type": "organization", "id": "9"}}]
    def index(org_bindings, status="collected"):
        fixture = copy.deepcopy(CASES[cid]["index"])
        project = fixture["project"][0]["data"]
        project["_ancestry"] = ancestry
        if status is not None:
            project["_inherited_iam_policies"] = [{"name": "organizations/9", "bindings": org_bindings, "ancestor": "organizations/9"}]
            project["_coverage"] = {"_inherited_iam_policies": {"status": status}}
        return fixture
    reader = copy.deepcopy(CASES[cid]["pass"])
    assert REGISTRY[cid].evaluate(reader, index([]))[0] == "PASS"
    grant = [{"role": "projects/p/roles/writer", "members": ["serviceAccount:reader@p.iam.gserviceaccount.com"]}]
    status, evidence = REGISTRY[cid].evaluate(reader, index(grant))
    assert status == "FAIL" and "organizations/9" in str(evidence)
    # Without complete ancestor evidence the organization grant is not visible.
    assert REGISTRY[cid].evaluate(reader, index(grant, status="partial"))[0] == "UNKNOWN"
    assert REGISTRY[cid].evaluate(reader, index(grant, status=None))[0] == "UNKNOWN"
