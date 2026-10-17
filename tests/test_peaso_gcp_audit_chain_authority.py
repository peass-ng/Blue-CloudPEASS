"""An effective audit chain belongs to its selected hierarchy root."""
import copy
import pytest
from peaso.checks import evaluate_check
from tests.test_peaso_gcp_audit_shared_followup import policy

CID = "gcp.iam.data_access_audit"

@pytest.mark.parametrize("mutation", ["foreign_root", "duplicate", "project_ancestor", "malformed_ancestor", "missing_scope", "unavailable_scope"])
def test_generic_audit_rejects_unbound_or_ambiguous_chain(mutation):
    item = policy()
    entries = item["effectiveAuditConfigs"]
    if mutation == "foreign_root": entries[0]["scope"] = "projects/foreign"
    elif mutation == "duplicate": entries.append(copy.deepcopy(entries[1]))
    elif mutation == "project_ancestor": entries[1]["scope"] = "projects/foreign"
    elif mutation == "malformed_ancestor": entries[1]["scope"] = "organizations/"
    elif mutation == "missing_scope": entries[0].pop("scope")
    elif mutation == "unavailable_scope": entries[0]["_coverage"] = {"scope": {"status": "partial"}}
    assert evaluate_check(CID, item)[0] == "UNKNOWN"

@pytest.mark.parametrize("root", ["projects/p", "folders/12", "organizations/1"])
def test_generic_audit_complete_root_and_confirmed_empty(root):
    item = policy(); item["name"] = root
    item["effectiveAuditConfigs"] = [{"scope": root, "auditConfigs": item["effectiveAuditConfigs"][1]["auditConfigs"]}]
    assert evaluate_check(CID, item)[0] == "PASS"
    item["effectiveAuditConfigs"][0]["auditConfigs"] = []
    assert evaluate_check(CID, item)[0] == "FAIL"

@pytest.mark.parametrize("root", ["projects/", "organizations/", "folders/abc"])
def test_generic_audit_malformed_selected_root_is_unknown(root):
    item = policy(); item["name"] = root
    item["effectiveAuditConfigs"] = [{"scope": root, "auditConfigs": item["effectiveAuditConfigs"][1]["auditConfigs"]}]
    assert evaluate_check(CID, item)[0] == "UNKNOWN"
