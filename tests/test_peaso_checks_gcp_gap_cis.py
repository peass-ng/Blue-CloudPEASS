"""CIS GCP 1.5 / 3.10 gap natives: CIS-literal predicates and the upstream rows mapped to them."""
import copy
import glob
import json
import pytest
from peaso.checks import CHECKS, gcp_gap_cis as gap
from peaso.checks.fixtures import CASES
from tests.gcp_native_iam_test_inputs_20261020 import current_iam_fixture, PROJECT, SCOPE
from tests.test_gcp_native57_iam_kms_review_20261020 import block_network_and_auth

REGISTRY = {check.id: check for check in CHECKS if check.id in gap.IDS}
SA = "gcp.gap.iam_user_managed_sa_no_admin_roles"
FW = "gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only"


@pytest.mark.parametrize("cid", gap.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_fixture_truths(cid, case, wanted):
    fixture = current_iam_fixture(cid)
    item = {"collection_status": "denied"} if case == "denied" else fixture[case]
    index = fixture.get("index", {})
    before = copy.deepcopy((item, index))
    status, evidence = REGISTRY[cid].evaluate(item, index)
    assert status == wanted, evidence
    assert (item, index) == before


def _sa_eval(role, email="app@" + PROJECT + ".iam.gserviceaccount.com", project_id=PROJECT):
    index = current_iam_fixture(SA)["index"]
    index["iam_policy"][0]["data"]["bindings"] = [{"role": role, "members": ["serviceAccount:" + email]}]
    item = {"email": email, "projectId": project_id, "_provenance": {"scope": SCOPE}}
    return REGISTRY[SA].evaluate(item, index)


@pytest.mark.parametrize("role,wanted", [
    ("roles/owner", "FAIL"), ("roles/editor", "FAIL"), ("roles/iam.serviceAccountAdmin", "FAIL"), ("roles/compute.admin", "FAIL"),
    (SCOPE + "/roles/deployAdmin", "FAIL"), ("roles/viewer", "PASS"), ("roles/storage.objectCreator", "PASS"),
    # CIS *Admin/*admin is a suffix glob; the Prowler substring test would also flag this role.
    ("roles/compute.osAdminLogin", "PASS"),
])
def test_cis_1_5_admin_role_criteria(role, wanted):
    assert _sa_eval(role)[0] == wanted


def test_cis_1_5_only_user_managed_service_accounts():
    for email in ("123-compute@developer.gserviceaccount.com", PROJECT + "@appspot.gserviceaccount.com",
                  "service-123@gcp-sa-pubsub.iam.gserviceaccount.com", "x@other.iam.gserviceaccount.com"):
        assert _sa_eval("roles/owner", email=email)[0] == "NOT_APPLICABLE", email


def test_cis_1_5_incomplete_root_policy_evidence_is_unknown():
    fixture = current_iam_fixture(SA)
    index = fixture["index"]
    index["iam_policy"] = []
    assert REGISTRY[SA].evaluate(fixture["pass"], index)[0] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["context", "item-scope", "crm-number", "project-id"])
def test_cis_1_5_invalid_native_identity_stays_unknown(mutation):
    original = copy.deepcopy(CASES[SA])
    fixture = current_iam_fixture(SA)
    item, index = fixture["pass"], fixture["index"]
    assert REGISTRY[SA].evaluate(item, index)[0] == "PASS"
    if mutation == "context":
        index["context"]["provider"] = "aws"
    elif mutation == "item-scope":
        item["_provenance"]["scope"] = "projects/foreign-project"
    elif mutation == "crm-number":
        index["project"][0]["data"]["name"] = SCOPE
    elif mutation == "project-id":
        index["project"][0]["data"]["projectId"] = "foreign-project"
    assert REGISTRY[SA].evaluate(item, index)[0] == "UNKNOWN"
    assert CASES[SA] == original


def _fw(**fields):
    rule = {"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]}
    rule.update(fields)
    return REGISTRY[FW].evaluate(rule, {})[0]


def test_cis_3_10_source_ranges():
    assert _fw(sourceRanges=["35.235.240.0/20"]) == "PASS"
    assert _fw(sourceRanges=["130.211.0.0/22", "35.191.0.0/16"]) == "PASS"
    assert _fw(sourceRanges=["35.235.241.0/24"]) == "PASS"
    assert _fw(sourceRanges=["35.235.240.0/20", "0.0.0.0/0"]) == "FAIL"
    assert _fw(sourceRanges=["10.0.0.0/8"]) == "FAIL"
    # CIS lists no IPv6 range, so the IPv6 IAP range is outside the CIS allowlist.
    assert _fw(sourceRanges=["2600:2d00:1:7::/64"]) == "FAIL"
    assert _fw() == "FAIL"  # omitted sources default to 0.0.0.0/0
    assert _fw(sourceTags=["web"]) == "FAIL"
    assert _fw(allowed=[{"IPProtocol": "tcp", "ports": ["8080"]}], sourceRanges=["35.235.240.0/20"]) == "PASS"


def test_cis_3_10_applicability():
    assert _fw(direction="EGRESS", destinationRanges=["0.0.0.0/0"]) == "NOT_APPLICABLE"
    assert _fw(disabled=True) == "NOT_APPLICABLE"
    assert _fw(allowed=[{"IPProtocol": "udp"}], sourceRanges=["0.0.0.0/0"]) == "NOT_APPLICABLE"
    assert REGISTRY[FW].evaluate({"direction": "INGRESS", "denied": [{"IPProtocol": "all"}], "sourceRanges": ["0.0.0.0/0"]}, {})[0] == "NOT_APPLICABLE"
    assert _fw(allowed=[{"IPProtocol": "all"}], sourceRanges=["0.0.0.0/0"]) == "FAIL"
    assert _fw(sourceRanges=["not-a-cidr"]) == "UNKNOWN"


def _rows():
    rows = {}
    for path in glob.glob("peaso/rulepacks/reviewed_*.json"):
        data = json.load(open(path))
        if isinstance(data, dict):
            rows.update({key: row for key, row in data.items() if isinstance(row, dict)})
    return rows


@pytest.mark.parametrize("native,keys", [
    (SA, ["gcp-compliance.control.cis_v%s_1_5" % v for v in ("120", "130", "200", "300", "400")]
         + ["gcp-compliance.control.iam_service_account_without_admin_privilege", "prowler.gcp.iam_sa_no_administrative_privileges"]),
    (FW, ["gcp-compliance.control.cis_v%s_3_10" % v for v in ("130", "200", "300", "400")]
         + ["gcp-compliance.control.compute_firewall_allow_tcp_connections_proxied_by_iap"]),
])
def test_upstream_rows_map_to_gap_natives_with_verification(native, keys):
    rows = _rows()
    for key in keys:
        row = rows[key]
        assert row["disposition"] == "merged" and row["native_checks"] == [native], key
        verification = row["native_equivalence_verification"]
        assert verification["verdict"] == "same_control_requirement" and verification["target_native_checks"] == [native]
        assert "native_equivalence_rejection" not in row


OFF = "gcp.gap.sql_3625_trace_flag_off_cis_v1"
ON = "gcp.ports.sql_instance_sql_3625_trace_database_flag_on"


def test_3625_off_native_is_literal_cis_v1_and_low_severity():
    check = REGISTRY[OFF]
    assert check.severity == "low"
    assert check.evaluate({"databaseVersion": "SQLSERVER_2019_STANDARD", "settings": {"databaseFlags": []}}, {})[0] == "FAIL"
    assert check.evaluate({"databaseVersion": "POSTGRES_15", "settings": {"databaseFlags": []}}, {})[0] == "NOT_APPLICABLE"


def test_3625_rows_follow_each_benchmark_versions_literal_requirement():
    rows = _rows()
    for key in ("cis_v120_6_3_6", "cis_v130_6_3_6"):
        row = rows["gcp-compliance.control." + key]
        assert row["native_checks"] == [OFF] and row["native_equivalence_verification"]["target_native_checks"] == [OFF]
    for key in ("cis_v200_6_3_6", "cis_v300_6_3_6", "cis_v400_6_3_6", "sql_instance_sql_3625_trace_database_flag_off"):
        assert rows["gcp-compliance.control." + key]["native_checks"] == [ON], key
