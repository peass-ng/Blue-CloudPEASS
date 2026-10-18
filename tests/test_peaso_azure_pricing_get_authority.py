"""Read-only pricing LIST discovery must bind each row to a full ARM GET."""
from copy import deepcopy
from urllib.parse import urlsplit, parse_qs

import pytest

from peaso.collectors import azure
from tests.archived_check_contract import evaluate_snapshot


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
LIST = SCOPE + "/providers/Microsoft.Security/pricings"
CONTROL = "azure.other.access_analysis_coverage"
FIM = "azure.cis.file_integrity_monitoring_component_status"


def pricing(name="CloudPosture", tier="Standard", *, props=True):
    row = {"id": LIST + "/" + name, "name": name,
           "type": "Microsoft.Security/pricings"}
    if props:
        row["properties"] = {"pricingTier": tier, "extensions": [],
                             "resourcesCoverageStatus": "FullyCovered"}
    return row


class Transport:
    tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"

    def __init__(self, listed, details, second_page=None):
        self.listed = listed
        self.details = details
        self.second_page = second_page
        self.calls = []

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience))
        assert audience == azure.ARM
        path = urlsplit(url).path
        if path == "/providers/Microsoft.ResourceGraph/resources":
            assert body is not None
            return {"data": [], "resultTruncated": "false"}
        assert body is None
        if path == LIST:
            if parse_qs(urlsplit(url).query).get("page") == ["2"]:
                response = self.second_page
            else:
                response = {"value": deepcopy(self.listed)}
                if self.second_page is not None:
                    response["nextLink"] = azure.ARM + LIST + "?page=2"
        else:
            assert path in self.details, path
            response = self.details[path]
        if isinstance(response, Exception):
            raise response
        return deepcopy(response)


def collected(api):
    snapshot = azure.collect({"scopes": [SCOPE], "options": {"retries": 0}},
                             ["security_pricing"], transport=api)
    inventory = next(c for c in snapshot["collections"] if c["type"] == "security_pricing")
    return snapshot, inventory


def status(snapshot, control=CONTROL):
    report = evaluate_snapshot(snapshot, checks=[control], include_not_applicable=True)
    return report["findings"][0]["status"]


@pytest.mark.parametrize("list_tier,get_tier,expected", [
    ("Free", "Standard", "UNKNOWN"),
    ("Standard", "Free", "FAIL"),
])
def test_cloudposture_get_is_authority_but_never_proves_analysis_coverage(list_tier, get_tier, expected):
    listed, detail = pricing(tier=list_tier), pricing(tier=get_tier)
    api = Transport([listed], {detail["id"]: detail})
    snapshot, inventory = collected(api)
    assert inventory["status"] == "collected"
    assert inventory["items"][0]["properties"]["pricingTier"] == get_tier
    provenance = inventory["items"][0]["_provenance"]
    assert all(provenance[key] == value for key, value in {
        "representation": "full", "source_operation": "get", "read_only": True,
        "api_version": "2024-01-01"}.items())
    assert "analysisCoverage" not in inventory["items"][0]
    assert status(snapshot) == expected
    assert [urlsplit(url).path for url, body, _ in api.calls if body is None] == [LIST, detail["id"]]
    assert all("api-version=2024-01-01" in url for url, body, _ in api.calls if body is None)


@pytest.mark.parametrize("detail,expected_inventory", [
    (azure.AzureReadError("denied", 403), "denied"),
    ({"id": LIST + "/CloudPosture"}, "malformed"),
    (pricing("CloudPosture", "Free") | {"id": SCOPE + "/providers/Microsoft.Security/pricings/Foreign"}, "malformed"),
])
def test_untrusted_get_cannot_turn_pricing_into_a_verdict(detail, expected_inventory):
    row = pricing(tier="Free")
    snapshot, inventory = collected(Transport([row], {row["id"]: detail}))
    assert inventory["status"] == "partial"
    assert inventory["items"][0]["detail"]["collection_status"] == expected_inventory
    assert status(snapshot) not in ("PASS", "FAIL")


def test_missing_list_properties_recovered_by_bound_get():
    listed, detail = pricing(props=False), pricing(tier="Free")
    snapshot, inventory = collected(Transport([listed], {detail["id"]: detail}))
    assert inventory["status"] == "collected"
    assert inventory["items"][0]["properties"]["pricingTier"] == "Free"
    assert status(snapshot) == "FAIL"


def test_partial_list_cannot_prove_free_failure():
    row = pricing(tier="Free")
    api = Transport([row], {row["id"]: row}, second_page=azure.AzureReadError("denied", 403))
    snapshot, inventory = collected(api)
    assert inventory["status"] == "partial"
    assert len(inventory["items"]) == 1
    assert status(snapshot) not in ("PASS", "FAIL")
    assert len([url for url, body, _ in api.calls if body is None]) == 3


def test_existing_virtualmachines_pricing_consumer_uses_full_get():
    listed = pricing("VirtualMachines", "Free")
    detail = pricing("VirtualMachines", "Standard")
    detail["properties"].update(subPlan="P2", extensions=[
        {"name": "FileIntegrityMonitoring", "isEnabled": "True"}])
    snapshot, inventory = collected(Transport([listed], {detail["id"]: detail}))
    assert inventory["status"] == "collected"
    assert status(snapshot, FIM) == "PASS"
