"""Operator-supplied kubelet metadata stays typed and node-bound."""

from datetime import datetime, timezone

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_k8s_component as new
from peaso.collectors.k8s import collect
from peaso.engine import evaluate_snapshot
from tests.test_peaso_checks_k8s_ports_collection import API
from tests.test_peaso_compliance_new_k8s_component_coverage import NodeAPI, NOW, NODES, request


OBSERVED_AT = datetime.now(timezone.utc).isoformat()
INDEX = {"context": {"metadata": {"cluster_id": "fixture"}}, "collections": {}}


def supplied_fields(component, configuration):
    api = API(total_pages=1, page_items=0)
    entry = {"component": component, "node_name": "node-a", "node_uid": "uid-a",
             "observed_at": OBSERVED_AT, "configuration": {**configuration,
             "clientSecret": "INERT_PRIVATE_TOKEN"}}
    snapshot = collect({"provider": "k8s", "options": {"inventories": ["component_configuration"],
                        "metadata_evidence": {"component_configuration": [entry]}},
                        "auth": {"cluster_id": "fixture"}}, api=api)
    assert api.calls == []
    return snapshot["collections"][0]


def supplied(component, value):
    return supplied_fields(component, {"podPidsLimit": value})


@pytest.mark.parametrize("limit", [4096, 0, -1])
def test_kubelet_pid_limit_preserves_observed_integer_without_inventing_safe_default(limit):
    collection = supplied("kubelet", limit)
    assert collection["status"] == "collected"
    item = collection["items"][0]
    assert item["configuration"] == {"podPidsLimit": limit}
    assert item["provenance"]["runtime_verified"] is False
    assert item["provenance"]["source"] == "operator-supplied metadata"
    assert (item["node_name"], item["node_uid"], item["observed_at"]) == ("node-a", "uid-a", OBSERVED_AT)
    assert item["id"] == "k8s://fixture/component_configuration/kubelet/node/uid-a"
    assert "INERT_PRIVATE_TOKEN" not in repr(item)


@pytest.mark.parametrize("value", [True, "4096", None, [4096], 1 << 63])
def test_kubelet_pid_limit_rejects_untyped_supplied_metadata(value):
    collection = supplied("kubelet", value)
    assert collection["status"] == "malformed"
    assert collection["items"] == []


def test_pid_limit_cannot_be_attributed_to_another_component():
    collection = supplied("kube-apiserver", 4096)
    assert collection["status"] == "malformed"
    assert collection["items"] == []


@pytest.mark.parametrize("field,configuration", [
    ("seccompDefault", {"seccompDefault": True}),
    ("featureGates.RotateKubeletServerCertificate", {"featureGates": {"RotateKubeletServerCertificate": False}}),
])
def test_kubelet_boolean_metadata_is_preserved_only_for_kubelet(field, configuration):
    collection = supplied_fields("kubelet", configuration)
    assert collection["status"] == "collected"
    item = collection["items"][0]
    expected = configuration if field == "seccompDefault" else {"featureGates": {"RotateKubeletServerCertificate": False}}
    assert item["configuration"] == expected
    assert "INERT_PRIVATE_TOKEN" not in repr(item)
    assert supplied_fields("kube-apiserver", configuration)["status"] == "malformed"


@pytest.mark.parametrize("configuration", [
    {"seccompDefault": "true"}, {"seccompDefault": 1},
    {"featureGates": {"RotateKubeletServerCertificate": "true"}},
    {"featureGates": {"RotateKubeletServerCertificate": 1}},
])
def test_kubelet_boolean_metadata_rejects_untyped_values(configuration):
    assert supplied_fields("kubelet", configuration)["status"] == "malformed"


def test_observed_kubelet_limit_truth_does_not_assert_cluster_completeness():
    cid = new.IDS[0]
    passing = supplied("kubelet", 4096)["items"][0]
    status, evidence = evaluate_check(cid, passing, INDEX)
    assert status == "PASS"
    assert "all-node coverage" in evidence["semantics"]
    assert evidence["scope_claim"] == "one observed kubelet declaration"
    assert evidence["cluster_declaration_coverage"] == "unknown"
    assert evaluate_check(cid, supplied("kubelet", 0)["items"][0], INDEX)[0] == "FAIL"
    assert evaluate_check(cid, supplied("kubelet", -1)["items"][0], INDEX)[0] == "FAIL"
    assert evaluate_check(cid, passing, {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {**passing, "provenance": {}}, INDEX)[0] == "UNKNOWN"
    assert evaluate_check(cid, {**passing, "provenance": {**passing["provenance"], "cluster_id": "other"}}, INDEX)[0] == "UNKNOWN"
    assert evaluate_check(cid, {**passing, "node_uid": "foreign-uid"}, INDEX)[0] == "UNKNOWN"
    assert evaluate_check(cid, new.CASES[cid]["missing"], {})[0] == "UNKNOWN"
    assert evaluate_check(cid, new.CASES[cid]["malformed"], {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {"collection_status": "denied"}, {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {"component": "kube-apiserver", "configuration": {"podPidsLimit": 4096}}, {})[0] == "NOT_APPLICABLE"


def test_observed_seccomp_declaration_and_historical_applicability():
    cid, configuration, legacy = new.IDS[1], {"seccompDefault": True}, "v1.21.9"
    item = supplied_fields("kubelet", configuration)["items"][0]
    status, evidence = evaluate_check(cid, item, INDEX)
    assert status == "PASS"
    assert "operator-attested" in evidence["semantics"]
    assert "unproved" in evidence["semantics"]
    assert evidence["observed_node_uid"] == "uid-a"
    assert evaluate_check(cid, item, {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {**item, "provenance": {}}, INDEX)[0] == "UNKNOWN"
    assert evaluate_check(cid, {**item, "provenance": {**item["provenance"], "cluster_id": "other"}}, INDEX)[0] == "UNKNOWN"
    false_config = {key: ({name: False for name in value} if isinstance(value, dict) else False)
                    for key, value in configuration.items()}
    assert evaluate_check(cid, supplied_fields("kubelet", false_config)["items"][0], INDEX)[0] == "FAIL"
    assert evaluate_check(cid, {"component": "kubelet", "configuration": configuration,
                                "kubeletVersion": legacy}, {})[0] == "NOT_APPLICABLE"
    assert evaluate_check(cid, {**item, "kubeletVersion": "v1.37.1"}, INDEX)[0] == "PASS"
    assert evaluate_check(cid, {**item, "kubeletVersion": "v1.38.0"}, INDEX)[0] == "UNKNOWN"
    assert evaluate_check(cid, {**item, "kubeletVersion": "unknown"}, INDEX)[0] == "UNKNOWN"
    assert evaluate_check(cid, new.CASES[cid]["missing"], {})[0] == "UNKNOWN"
    assert evaluate_check(cid, new.CASES[cid]["malformed"], {})[0] == "UNKNOWN"
    assert evaluate_check(cid, {"component": "kube-apiserver", "configuration": configuration}, {})[0] == "NOT_APPLICABLE"


def test_attested_pid_and_seccomp_rows_do_not_bypass_native_only_admission():
    rows = [{"component": "kubelet", "node_name": name, "node_uid": uid,
             "observed_at": NOW, "configuration": {"podPidsLimit": 4096, "seccompDefault": True}}
            for name, uid in NODES]
    snapshot = collect(request(rows=rows), api=NodeAPI())
    assert snapshot["metadata"]["component_configuration_coverage"]["status"] == "attested_complete"
    # Operator declarations remain archived; staged evaluator registration must
    # never make their owner-attested inputs eligible for automated assessments.
    with pytest.raises(ValueError, match="requires external policy or manual evidence"):
        evaluate_snapshot(snapshot, checks=new.IDS[:2])


def test_held_rotation_callback_keeps_historical_applicability_without_registry_claim():
    # Keep this historical node ID; the reviewed batch now registers only the
    # declaration predicate, while the callback's version caveats remain.
    cid = new.IDS[2]
    assert cid in {check.id for check in CHECKS}
    assert evaluate_check(cid, new.CASES[cid]["pass"], INDEX)[0] == "PASS"
    assert evaluate_check(cid, new.CASES[cid]["fail"], INDEX)[0] == "FAIL"
    assert evaluate_check(cid, {**new.CASES[cid]["pass"], "provenance": {}}, INDEX)[0] == "UNKNOWN"
    callback = new.kubelet_server_certificate_gate
    item = supplied_fields("kubelet", {"featureGates": {"RotateKubeletServerCertificate": True}})["items"][0]
    assert callback(item, INDEX)[0] == "PASS"
    assert callback({**item, "kubeletVersion": "v1.6.9"}, INDEX)[0] == "NOT_APPLICABLE"
    assert callback({**item, "kubeletVersion": "v1.37.1"}, INDEX)[0] == "PASS"
    assert callback({**item, "kubeletVersion": "v1.38.0"}, INDEX)[0] == "UNKNOWN"
    assert callback({**item, "kubeletVersion": "unknown"}, INDEX)[0] == "UNKNOWN"
    assert callback({"component": "kube-apiserver", "configuration": item["configuration"]}, INDEX)[0] == "NOT_APPLICABLE"
