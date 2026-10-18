"""Adversarial native-snapshot semantics for the implemented signed K8s rows."""
import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_k8s as new


def status(check_id, item):
    return evaluate_check(check_id, item, {})[0]


@pytest.mark.parametrize("check_id", [x for x in new.IDS if "effective_runtime_default_seccomp" in x])
def test_effective_seccomp_inheritance_and_override(check_id):
    cases = new.CASES[check_id]
    assert status(check_id, cases["pass"]) == "PASS"
    assert status(check_id, cases["fail"]) == "FAIL"
    assert status(check_id, cases["missing"]) == "UNKNOWN"
    windows = copy.deepcopy(cases["pass"])
    path = new._PODSPEC[check_id.removeprefix("k8s.cis.").removesuffix("_effective_runtime_default_seccomp")]
    spec = windows
    for part in path.split("."):
        spec = spec[part]
    spec["os"] = {"name": "windows"}
    assert status(check_id, windows) == "NOT_APPLICABLE"
    spec["os"] = {"name": "linux"}
    spec["containers"][0]["securityContext"] = {"seccompProfile": {"type": "RuntimeDefault"}}
    assert status(check_id, windows) == "PASS"
    spec["containers"][0]["securityContext"] = {"seccompProfile": {"type": "FutureProfile"}}
    assert status(check_id, windows) == "UNKNOWN"


@pytest.mark.parametrize("check_id", [x for x in new.IDS if "effective_runtime_default_seccomp" in x])
def test_effective_seccomp_repeated_evaluation_preserves_podspec_and_index(check_id):
    item = copy.deepcopy(new.CASES[check_id]["pass"])
    before = copy.deepcopy(item)
    scoped = {"context": {"cluster_id": "cluster-a"}}
    before_index = copy.deepcopy(scoped)
    first = evaluate_check(check_id, item, scoped)
    second = evaluate_check(check_id, item, scoped)
    assert first == second
    assert first[0] == "PASS" and first[1]["assessed_containers"] == 2
    assert item == before and scoped == before_index


@pytest.mark.parametrize("direction", ["ingress", "egress"])
def test_namespace_wide_allow_and_selector_scope(direction):
    check_id = f"k8s.cis.networkpolicy_no_default_allow_{direction}"
    cases = new.CASES[check_id]
    assert status(check_id, cases["pass"]) == "PASS"
    assert status(check_id, cases["fail"]) == "FAIL"
    narrowed = copy.deepcopy(cases["fail"])
    narrowed["spec"]["podSelector"] = {"matchLabels": {"app": "api"}}
    assert status(check_id, narrowed) == "NOT_APPLICABLE"
    malformed = copy.deepcopy(cases["pass"])
    malformed["spec"][direction][0]["from" if direction == "ingress" else "to"] = "anywhere"
    assert status(check_id, malformed) == "UNKNOWN"
    invalid_peer = copy.deepcopy(cases["pass"])
    invalid_peer["spec"][direction][0]["from" if direction == "ingress" else "to"] = [{"ipBlock": {"cidr": True}}]
    assert status(check_id, invalid_peer) == "UNKNOWN"
    empty_peer = copy.deepcopy(cases["pass"])
    empty_peer["spec"][direction][0]["from" if direction == "ingress" else "to"] = [{}]
    assert status(check_id, empty_peer) == "UNKNOWN"
    invalid_selector = copy.deepcopy(cases["pass"])
    invalid_selector["spec"]["podSelector"] = {"matchLabels": {"app": True}}
    assert status(check_id, invalid_selector) == "UNKNOWN"
    partial_selector = copy.deepcopy(cases["pass"])
    del partial_selector["spec"]["podSelector"]
    assert status(check_id, partial_selector) == "UNKNOWN"
    partial_types = copy.deepcopy(cases["pass"])
    del partial_types["spec"]["policyTypes"]
    assert status(check_id, partial_types) == "UNKNOWN"


def test_deployment_availability_requires_both_condition_and_replica_fact():
    check_id = "k8s_deployment_available_condition"
    cases = new.CASES[check_id]
    assert status(check_id, cases["pass"]) == "PASS"
    assert status(check_id, cases["fail"]) == "FAIL"
    without_condition = copy.deepcopy(cases["pass"])
    without_condition["status"]["conditions"] = []
    assert status(check_id, without_condition) == "UNKNOWN"
    without_available = copy.deepcopy(cases["pass"])
    del without_available["status"]["availableReplicas"]
    assert status(check_id, without_available) == "UNKNOWN"


def test_ingress_sni_matches_rule_hosts_to_named_tls_secret():
    check_id = "k8s_ingress_sni_hosts"
    cases = new.CASES[check_id]
    assert status(check_id, cases["pass"]) == "PASS"
    assert status(check_id, cases["fail"]) == "FAIL"
    empty_secret = copy.deepcopy(cases["pass"])
    empty_secret["spec"]["tls"][0]["secretName"] = ""
    assert status(check_id, empty_secret) == "FAIL"
    malformed = copy.deepcopy(cases["pass"])
    malformed["spec"]["tls"][0]["hosts"] = "app.example.org"
    assert status(check_id, malformed) == "UNKNOWN"


def test_ingress_tls_requires_complete_same_namespace_secret_metadata():
    cid = "k8s_ingress_tls_configured"
    assert next(check.dependencies for check in CHECKS if check.id == cid) == ["ingress", "secret_metadata"]
    ingress = new.CASES[cid]["pass"]
    def inventory(rows, state="collected"):
        return {"collections": {"secret_metadata": [{"status": state}]},
                "secret_metadata": [{"data": row} for row in rows]}
    secret = {"metadata": {"name": "app-tls", "namespace": "apps"}, "type": "kubernetes.io/tls"}
    assert evaluate_check(cid, ingress, inventory([secret]))[0] == "PASS"
    assert evaluate_check(cid, new.CASES[cid]["fail"], inventory([secret]))[0] == "FAIL"
    wrong_namespace = {**secret, "metadata": {"name": "app-tls", "namespace": "other"}}
    assert evaluate_check(cid, ingress, inventory([wrong_namespace]))[0] == "FAIL"
    assert evaluate_check(cid, ingress, inventory([wrong_namespace, secret]))[0] == "PASS"
    assert evaluate_check(cid, ingress, inventory([secret, secret]))[0] == "UNKNOWN"
    wrong_type = {**secret, "type": "Opaque"}
    assert evaluate_check(cid, ingress, inventory([wrong_type]))[0] == "FAIL"
    assert evaluate_check(cid, ingress, inventory([], "empty"))[0] == "FAIL"
    assert evaluate_check(cid, ingress, inventory([], "denied"))[0] == "UNKNOWN"
    assert evaluate_check(cid, ingress, {})[0] == "UNKNOWN"
    malformed = copy.deepcopy(ingress)
    malformed["spec"]["tls"][0]["hosts"] = "app.example.org"
    assert evaluate_check(cid, malformed, inventory([secret]))[0] == "UNKNOWN"
    blank_name = copy.deepcopy(ingress)
    blank_name["spec"]["tls"][0]["secretName"] = ""
    assert evaluate_check(cid, blank_name, inventory([secret]))[0] == "FAIL"
    absent_tls = copy.deepcopy(ingress)
    absent_tls["spec"]["tls"] = []
    assert evaluate_check(cid, absent_tls, inventory([secret]))[0] == "FAIL"
    assert evaluate_check(cid, absent_tls, inventory([], "denied"))[0] == "UNKNOWN"


def test_clusterip_ftp_declaration_and_scope():
    check_id = "k8s_service_service_uses_ftp_endpoint_connection_e9b0a5f836"
    cases = new.CASES[check_id]
    assert status(check_id, cases["pass"]) == "PASS"
    assert status(check_id, cases["fail"]) == "FAIL"
    other_type = copy.deepcopy(cases["fail"])
    other_type["spec"]["type"] = "NodePort"
    assert status(check_id, other_type) == "NOT_APPLICABLE"
    malformed = copy.deepcopy(cases["pass"])
    malformed["spec"]["ports"][0]["port"] = "21"
    assert status(check_id, malformed) == "UNKNOWN"


@pytest.mark.parametrize("check_id,field", [
    ("k8s_node_nodes_publicly_accessible_rule_non_8250b02a65", "addresses"),
    ("k8s_pod_direct_internet_access_disabled_pod_0a30afe8f2", "podIPs"),
])
def test_global_ip_signals_are_address_declarations_only(check_id, field):
    cases = new.CASES[check_id]
    assert status(check_id, cases["pass"]) == "PASS"
    failed, evidence = evaluate_check(check_id, cases["fail"], {})
    assert failed == "FAIL"
    assert "no internet reachability is inferred" in evidence["semantics"]
    missing = copy.deepcopy(cases["pass"])
    del missing["status"][field]
    if check_id.startswith("k8s_node"):
        assert status(check_id, missing) == "UNKNOWN"
    else:
        del missing["status"]["podIP"]
        assert status(check_id, missing) == "UNKNOWN"
    malformed = copy.deepcopy(cases["pass"])
    if check_id.startswith("k8s_node"):
        malformed["status"]["addresses"][0]["address"] = "invalid-ip"
    else:
        malformed["status"]["podIP"] = "invalid-ip"
    assert status(check_id, malformed) == "UNKNOWN"
    ipv6 = copy.deepcopy(cases["pass"])
    if check_id.startswith("k8s_node"):
        ipv6["status"]["addresses"][0]["address"] = "2001:4860:4860::8888"
    else:
        ipv6["status"]["podIP"] = "2001:4860:4860::8888"
        ipv6["status"]["podIPs"] = [{"ip": "2001:4860:4860::8888"}]
    assert status(check_id, ipv6) == "FAIL"


def test_secret_metadata_only_deletion_state_and_denial():
    cid = "k8s_secret_no_deletion_timestamp"
    cases = new.CASES[cid]
    assert status(cid, cases["pass"]) == "PASS"
    assert status(cid, cases["fail"]) == "FAIL"
    assert status(cid, {"metadata": {"name": "s", "namespace": "apps", "deletionTimestamp": "bad"}}) == "UNKNOWN"
    denied = {"metadata": {"name": "s", "namespace": "apps", "_coverage": {"deletionTimestamp": {"status": "denied"}}}}
    assert status(cid, denied) == "UNKNOWN"
    assert status(cid, {"metadata": {"name": "s"}}) == "UNKNOWN"
