"""Control-plane endpoint facts: malformed/denied input cannot imply safety."""
import pytest
from peaso.checks import CHECKS

REGISTRY = {c.id: c for c in CHECKS}


@pytest.mark.parametrize("cidr", ["garbage", "", None, "300.1.1.1/32"])
def test_aks_malformed_cidr_is_unknown(cidr):
    item = {"properties": {"apiServerAccessProfile": {"authorizedIPRanges": [cidr]}}}
    assert REGISTRY["azure.aks.api_server_restricted"].evaluate(item, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_noncanonical_ipv6_unrestricted_range_is_not_a_pass(provider):
    if provider == "azure":
        cid = "azure.aks.api_server_restricted"
        item = {"properties": {"apiServerAccessProfile": {"authorizedIPRanges": ["0:0:0:0:0:0:0:0/0"]}}}
    else:
        cid = "gcp.gke.control_plane_restricted"
        item = {"name": "fixture", "masterAuthorizedNetworksConfig": {"enabled": True, "cidrBlocks": [{"cidrBlock": "0:0:0:0:0:0:0:0/0"}]}}
    assert REGISTRY[cid].evaluate(item, {})[0] == "FAIL"


def test_aks_explicit_field_denial_overrides_present_restrictions():
    profile = {"authorizedIPRanges": ["203.0.113.0/24"], "_coverage": {"authorizedIPRanges": {"status": "denied"}}}
    assert REGISTRY["azure.aks.api_server_restricted"].evaluate({"properties": {"apiServerAccessProfile": profile}}, {})[0] == "UNKNOWN"


def test_gke_dns_only_is_not_falsely_labelled_public_ip_or_private_dns():
    item = {"name": "fixture", "controlPlaneEndpointsConfig": {
        "ipEndpointsConfig": {"enabled": False}, "dnsEndpointConfig": {"endpoint": "fixture.gke.goog", "allowExternalTraffic": True}}}
    status, evidence = REGISTRY["gcp.gke.control_plane_restricted"].evaluate(item, {})
    assert status == "NOT_APPLICABLE"
    assert evidence["dns_external_traffic"] is True and evidence["dns_endpoint_present"] is True
    assert "private_endpoint" not in evidence


@pytest.mark.parametrize("blocks", [[{}], [{"cidrBlock": "bad"}], [{"cidrBlock": None}]])
def test_gke_malformed_authorized_networks_are_unknown(blocks):
    item = {"name": "fixture", "masterAuthorizedNetworksConfig": {"enabled": True, "cidrBlocks": blocks}}
    assert REGISTRY["gcp.gke.control_plane_restricted"].evaluate(item, {})[0] == "UNKNOWN"


def test_gke_modern_endpoint_restrictions_and_denied_boolean():
    endpoint = {"enabled": True, "enablePublicEndpoint": True, "authorizedNetworksConfig": {"enabled": True, "cidrBlocks": [{"cidrBlock": "203.0.113.0/24"}]}}
    item = {"name": "fixture", "controlPlaneEndpointsConfig": {"ipEndpointsConfig": endpoint}}
    assert REGISTRY["gcp.gke.control_plane_restricted"].evaluate(item, {})[0] == "PASS"
    endpoint["_coverage"] = {"enabled": {"status": "denied"}}
    assert REGISTRY["gcp.gke.control_plane_restricted"].evaluate(item, {})[0] == "UNKNOWN"


def test_gke_provider_wide_public_sources_require_review_not_a_narrow_cidr_pass():
    item = {"name": "fixture", "masterAuthorizedNetworksConfig": {"enabled": True,
        "cidrBlocks": [{"cidrBlock": "203.0.113.0/24"}], "gcpPublicCidrsAccessEnabled": True}}
    status, evidence = REGISTRY["gcp.gke.control_plane_restricted"].evaluate(item, {})
    assert status == "MANUAL" and evidence["gcp_public_cidrs_access"] is True


@pytest.mark.parametrize("provider,kind,item", [
    ("gcp", "gke_cluster", {"name": "fixture", "controlPlaneEndpointsConfig": {
        "ipEndpointsConfig": {"enabled": False}, "dnsEndpointConfig": {"endpoint": "fixture.gke.goog", "allowExternalTraffic": True}}}),
    ("azure", "aks_cluster", {"id": "fixture", "properties": {"apiServerAccessProfile": {"authorizedIPRanges": ["invalid"]}}}),
])
def test_exposure_projection_does_not_contradict_unknown_endpoint_facts(provider, kind, item):
    from peaso.analysis.internet_exposure import internet_findings
    from peaso.snapshot import make_snapshot, resources
    snapshot = make_snapshot(provider, ["fixture"], [{"type": kind, "scope": "fixture", "status": "collected", "items": [item]}])
    findings = internet_findings(snapshot, resources(snapshot))
    assert findings and {finding["status"] for finding in findings} == {"UNKNOWN"}
