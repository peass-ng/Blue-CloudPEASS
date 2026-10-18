"""Truth fixtures for entity applicability, scope joins and literal predicates."""
import copy
import pytest
from peaso.checks import CHECKS, gcp_ports_perimeter as ports
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




@pytest.mark.parametrize("kind", ["bigtable_instance", "billing_account", "function", "cloudrun_job", "cloudrun_service"])
def test_trust_parameters_are_required_and_project_exceptions_remain_manual(kind):
    check = next(check for check in REGISTRY.values() if check.kind == kind and check.id.endswith("policy_shared_access"))
    fixture = CASES[check.id]
    assert check.evaluate(fixture["pass"], {})[0] == "UNKNOWN"
    assert check.evaluate({"iamPolicy": {"bindings": []}}, {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": ["projectViewer:p"]}]}}, fixture["index"])[0] == "MANUAL"
    item = copy.deepcopy(fixture["fail"])
    item["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2026-01-01T00:00:00Z')"}
    status, evidence = check.evaluate(item, fixture["index"])
    assert status == "FAIL" and evidence["untrusted_nonproject_declarations"][0]["condition"]


def test_iap_presence_with_broad_source_is_not_proxy_only_restriction():
    cid = ports.REFERENCE_SPECS["firewall_iap_tcp_proxy_source_restriction"]
    fixture = CASES[cid]
    assert "35.235.240.0/20" in fixture["fail"]["sourceRanges"]  # SQL containment says OK with an added 0/0.
    assert REGISTRY[cid].evaluate(fixture["fail"], {})[0] == "FAIL"
    item = copy.deepcopy(fixture["pass"])
    item["sourceRanges"] = ["2600:2d00:1:7::/64"]
    assert REGISTRY[cid].evaluate(item, {})[0] == "PASS"
    item["direction"] = "EGRESS"
    assert REGISTRY[cid].evaluate(item, {})[0] == "NOT_APPLICABLE"
    item["direction"] = "INGRESS"
    item["sourceRanges"] = ["not-a-cidr"]
    assert REGISTRY[cid].evaluate(item, {})[0] == "UNKNOWN"


def test_http_proxy_policy_is_distinct_from_iap_tcp_source_ranges():
    http = REGISTRY[ports.REFERENCE_SPECS["firewall_http_lb_proxy_source_restriction"]]
    tcp = REGISTRY[ports.REFERENCE_SPECS["firewall_iap_tcp_proxy_source_restriction"]]
    item = CASES[http.id]["pass"]
    assert http.evaluate(item, {})[0] == "PASS"
    assert tcp.evaluate(item, {})[0] == "FAIL"


def test_sql_authorized_network_ipv6_source_false_clean_and_both_current_modes():
    cid = ports.REFERENCE_SPECS["sql_instance_not_open_to_internet"]
    fixture = CASES[cid]
    ranges = [row["value"] for row in fixture["fail"]["settings"]["ipConfiguration"]["authorizedNetworks"]]
    assert "0.0.0.0/0" not in ranges  # Prowler's IPv4-only loop says PASS.
    assert REGISTRY[cid].evaluate(fixture["fail"], {})[0] == "FAIL"
    ssl = REGISTRY[ports.REFERENCE_SPECS["reference_sql_ssl_connections"]]
    for mode in ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"):
        assert ssl.evaluate({"settings": {"ipConfiguration": {"sslMode": mode}}}, {})[0] == "PASS"
    assert ssl.evaluate({"settings": {"ipConfiguration": {"sslMode": "NEW_MODE"}}}, {})[0] == "UNKNOWN"


def test_nonempty_broad_caller_object_is_not_meaningful_restriction():
    cid = ports.REFERENCE_SPECS["api_key_meaningful_restrictions"]
    fixture = CASES[cid]
    assert fixture["fail"]["restrictions"] != {}  # Source considers configured.
    assert REGISTRY[cid].evaluate(fixture["fail"], {})[0] == "FAIL"
    assert REGISTRY[cid].evaluate({"restrictions": {"apiTargets": [{"service": "cloudapis.googleapis.com"}]}}, {})[0] == "FAIL"


def test_dataset_text_false_alarm_and_legacy_acl_false_clean():
    cid = ports.REFERENCE_SPECS["bigquery_dataset_public_acl_declarations"]
    fixture = CASES[cid]
    authorized_view = {"access": [{"view": {"projectId": "p", "datasetId": "d", "tableId": "allUsers"}}]}
    assert "allUsers" in str(authorized_view["access"])  # Prowler scans arbitrary nested text.
    assert REGISTRY[cid].evaluate(authorized_view, {})[0] == "PASS"
    assert all(row.get("iamMember") not in ("allUsers", "allAuthenticatedUsers") for row in fixture["fail"]["access"])
    assert REGISTRY[cid].evaluate(fixture["fail"], {})[0] == "FAIL"  # Perimeter source omits specialGroup.


def test_function_internal_ingress_does_not_require_outbound_connector():
    cid = ports.REFERENCE_SPECS["function_internal_ingress_declaration"]
    item = CASES[cid]["pass"]
    assert "vpcConnector" not in item["serviceConfig"]  # Perimeter SQL alarms despite internal ingress.
    assert REGISTRY[cid].evaluate(item, {})[0] == "PASS"


def test_cloudrun_any_role_public_declaration_is_not_invoker_only():
    cid = ports.REFERENCE_SPECS["cloud_run_service_policy_prohibit_public_access"]
    item = CASES[cid]["fail"]
    assert item["iamPolicy"]["bindings"][0]["role"] != "roles/run.invoker"
    assert REGISTRY[cid].evaluate(item, {})[0] == "FAIL"
