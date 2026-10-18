"""Inert registered service snapshots for selected publication fact authority."""
import copy
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "k8s.service.review_public_type"
INTERNAL = "service.beta.kubernetes.io/aws-load-balancer-internal"
SOURCE = "service.beta.kubernetes.io/load-balancer-source-ranges"

def deny(row, key):
    row.setdefault("_coverage", {})[key] = {"status": "denied"}

def observed(item):
    snapshot = make_snapshot("k8s", ["*"], [{"type": "service", "scope": "*", "status": "collected", "items": [copy.deepcopy(item)]}], created_at="2026-10-17T00:00:00Z")
    before = copy.deepcopy(snapshot)
    findings = [row for row in evaluate_snapshot(snapshot, checks=[CID])["findings"] if row["check_id"] == CID]
    assert snapshot == before and len(findings) == 1
    return findings[0]["status"]

@pytest.mark.parametrize("field", ["type", "externalIPs"])
def test_denied_consumed_type_and_external_ips(field):
    spec = {"type": "ClusterIP", "externalIPs": []}; deny(spec, field)
    assert observed({"spec": spec}) == "UNKNOWN"

def test_denied_lb_ranges_cannot_prove_private():
    spec = {"type": "LoadBalancer", "loadBalancerSourceRanges": ["10.0.0.0/8"]}; deny(spec, "loadBalancerSourceRanges")
    assert observed({"spec": spec}) == "UNKNOWN"

@pytest.mark.parametrize("key,value", [(INTERNAL, "true"), (SOURCE, "10.0.0.0/8")])
def test_denied_literal_annotations_cannot_prove_private(key, value):
    annotations = {key: value}; deny(annotations, key)
    assert observed({"spec": {"type": "LoadBalancer"}, "metadata": {"annotations": annotations}}) == "UNKNOWN"

def test_denied_annotations_container_cannot_prove_private():
    metadata = {"annotations": {INTERNAL: "true"}}; deny(metadata, "annotations")
    assert observed({"spec": {"type": "LoadBalancer"}, "metadata": metadata}) == "UNKNOWN"

def test_irrelevant_lb_facts_do_not_block_other_service_types():
    for service_type, expected in (("ClusterIP", "PASS"), ("NodePort", "FAIL")):
        spec = {"type": service_type, "loadBalancerSourceRanges": ["10.0.0.0/8"]}; deny(spec, "loadBalancerSourceRanges")
        annotations = {INTERNAL: "true", SOURCE: "10.0.0.0/8"}; deny(annotations, INTERNAL); deny(annotations, SOURCE)
        assert observed({"spec": spec, "metadata": {"annotations": annotations}}) == expected

def test_independent_publication_survives_unavailable_peers():
    spec = {"type": "ClusterIP", "externalIPs": ["203.0.113.1"]}; deny(spec, "type")
    assert observed({"spec": spec}) == "FAIL"
    spec = {"type": "LoadBalancer", "externalIPs": ["203.0.113.1"], "loadBalancerSourceRanges": ["10.0.0.0/8"]}; deny(spec, "loadBalancerSourceRanges")
    assert observed({"spec": spec}) == "FAIL"
    spec = {"type": "LoadBalancer", "loadBalancerSourceRanges": ["10.0.0.0/8"]}; deny(spec, "loadBalancerSourceRanges")
    assert observed({"spec": spec, "metadata": {"annotations": {SOURCE: "0.0.0.0/0"}}}) == "FAIL"

def test_existing_provider_heuristics_and_native_omissions():
    assert observed({"spec": {"type": "LoadBalancer"}, "metadata": {"annotations": {INTERNAL: "true"}}}) == "PASS"
    assert observed({"spec": {"type": "LoadBalancer"}, "metadata": {"annotations": {SOURCE: "10.0.0.0/8"}}}) == "PASS"
    assert observed({"spec": {"type": "LoadBalancer"}}) == "FAIL"
    assert observed({"spec": {}}) == "PASS"
    assert observed({"spec": {"type": "ClusterIP", "externalIPs": ["203.0.113.1"]}}) == "FAIL"


def test_internal_load_balancer_is_decisive_without_unrelated_ranges():
    spec={"type":"LoadBalancer"};deny(spec,"loadBalancerSourceRanges")
    assert observed({"spec":spec,"metadata":{"annotations":{INTERNAL:"true"}}})=="PASS"

def test_known_internal_annotation_survives_unreadable_alternate_provider():
    annotations={INTERNAL:"true"};deny(annotations,"cloud.google.com/load-balancer-type")
    assert observed({"spec":{"type":"LoadBalancer"},"metadata":{"annotations":annotations}})=="PASS"

@pytest.mark.parametrize("source",["0.0.0.1/0","::1/0"])
def test_prefix_zero_is_broad_regardless_host_bits(source):
    assert observed({"spec":{"type":"LoadBalancer","loadBalancerSourceRanges":[source]}})=="FAIL"

@pytest.mark.parametrize("address",["not-an-ip","192.0.2.1/24"])
def test_malformed_external_ip_cannot_prove_publication(address):
    assert observed({"spec":{"type":"ClusterIP","externalIPs":[address]}})=="UNKNOWN"
