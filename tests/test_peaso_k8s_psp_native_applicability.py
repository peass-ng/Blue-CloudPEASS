"""Native PSP resource applicability is limited to proven API removal."""
import copy
import json
import os
from pathlib import Path

import pytest

from peaso import engine
from peaso.snapshot import make_snapshot

HERE = Path(__file__).resolve().parent
FIXTURE = json.loads((HERE / "fixtures/native_psp_absent.json").read_text())
IDS = frozenset({
    "k8s.ports.podsecuritypolicy.pod_security_policy_container_privilege_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_hostpid_sharing_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_hostipc_sharing_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_host_network_access_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_container_privilege_escalation_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_immutable_container_filesystem",
    "k8s.ports.podsecuritypolicy.pod_security_policy_non_root_container",
    "k8s.claude.podsecuritypolicy.allowed_host_path_restricted",
    "k8s.claude.podsecuritypolicy.default_seccomp_profile",
    "k8s.claude.podsecuritypolicy.security_services_hardening",
})


def fixture_snapshot(change=None):
    native = copy.deepcopy(FIXTURE)
    if change:
        change(native)
    return make_snapshot("k8s", ["*"], native["collections"], metadata=native["metadata"])


def result(snapshot, ids=IDS):
    report = engine.evaluate_snapshot(snapshot, checks=sorted(ids), include_not_applicable=True)
    findings = {f["check_id"]: f for f in report["findings"] if f["check_id"] in ids}
    assert set(findings) == set(ids)
    return report, findings


def psp(native):
    return native["collections"][0]


def discovery(native):
    return native["collections"][1]


def item(native):
    return discovery(native)["items"][0]


def test_registered_contract_and_native_fixture():
    assert engine._PSP_RESOURCE_CHECK_IDS == IDS
    _, selected = engine._selection("k8s", None, sorted(IDS), None)
    assert {check.id for check in selected} == IDS
    assert all(check.kind == "podsecuritypolicy" and check.target == "resource" for check in selected)
    report, findings = result(fixture_snapshot())
    assert {f["status"] for f in findings.values()} == {"NOT_APPLICABLE"}
    assert all(f["resource_id"] == "inventory:podsecuritypolicy" for f in findings.values())
    assert all("no secure admission" in f["evidence"]["semantics"] for f in findings.values())
    coverage = next(c for c in report["coverage"] if c["level"] == "collection" and c["type"] == "podsecuritypolicy")
    assert coverage["status"] == "not_applicable"
    assert coverage["error_code"] == "pod_security_policy_api_absent"
    assert all(f["status"] != "PASS" for f in findings.values())


def test_actual_saved_snapshot_replay_if_available():
    path = os.environ.get("PEASO_PSP_NATIVE_SNAPSHOT")
    if path is None:
        path = HERE.parents[3] / "native-wave26/k8s-current-ready/snapshot.json"
    path = Path(path)
    if not path.is_file():
        pytest.skip("saved native snapshot is not part of the portable source checkout")
    snapshot = json.loads(path.read_text())
    original_digest = snapshot["snapshot_id"]
    _, findings = result(snapshot)
    assert {f["status"] for f in findings.values()} == {"NOT_APPLICABLE"}
    assert snapshot["snapshot_id"] == original_digest


def _missing_discovery(native):
    native["collections"].pop()


def _wrong_scope(native):
    discovery(native)["scope"] = "other"


def _wrong_cluster(native):
    item(native)["provenance"]["cluster_id"] = "foreign-cluster"


def _wrong_id(native):
    item(native)["id"] = "k8s://foreign-cluster/api-discovery"


def _missing_cluster(native):
    native["metadata"].pop("cluster_id")


def _denied_discovery(native):
    discovery(native).update(status="denied", items=[], error={"code": "Forbidden"})


def _conflicting_advertisement(native):
    item(native)["podSecurityPolicyAdvertised"] = True


def _coverage_gap(native):
    item(native)["_coverage"] = {"podSecurityPolicyAdvertised": {"status": "denied"}}


def _missing_version(native):
    item(native).pop("serverVersion")


def _version(native, value):
    item(native)["serverVersion"]["gitVersion"] = value
    psp(native)["applicability"]["kubernetes_version"] = value


def _stale_marker(native):
    psp(native)["applicability"]["kubernetes_version"] = "v1.25.0"


def _missing_marker(native):
    psp(native).pop("coverage_status")


def _conflicting_marker(native):
    psp(native)["error"]["code"] = "api_discovery_incomplete"


@pytest.mark.parametrize("change", [
    _missing_discovery, _wrong_scope, _wrong_cluster, _wrong_id,
    _missing_cluster, _denied_discovery, _conflicting_advertisement,
    _coverage_gap, _missing_version, _stale_marker, _missing_marker,
    _conflicting_marker,
    lambda n: _version(n, "v1.24.9"),
    lambda n: _version(n, "v1.25.0-alpha.1"),
    lambda n: _version(n, "v1.26.0-rc.2"),
    lambda n: _version(n, "v1.26.0-preview.1"),
    lambda n: _version(n, "v1.36junk"),
    lambda n: _version(n, "v" + "9" * 5000 + ".25.0"),
], ids=[
    "missing-discovery", "foreign-scope", "foreign-cluster", "foreign-id",
    "missing-cluster", "denied-discovery", "conflicting-advertisement",
    "discovery-gap", "missing-version", "stale-marker", "missing-marker",
    "conflicting-marker", "old-version", "alpha", "release-candidate", "preview",
    "malformed-version", "pathological-version",
])
def test_incomplete_or_conflicting_proof_stays_unknown(change):
    report, findings = result(fixture_snapshot(change))
    assert {f["status"] for f in findings.values()} == {"UNKNOWN"}
    assert all(f["status"] != "PASS" for f in findings.values())
    coverage = next(c for c in report["coverage"] if c["level"] == "collection" and c["type"] == "podsecuritypolicy")
    assert coverage["status"] == "not_collected"


def test_supported_124_evaluates_real_resource():
    def change(native):
        _version(native, "v1.24.9")
        item(native)["podSecurityPolicyAdvertised"] = True
        native["collections"][0] = {
            "type": "podsecuritypolicy", "scope": "*", "service": "kubernetes",
            "status": "collected", "items": [{"id": "k8s://fixture/podsecuritypolicy/test",
                "metadata": {"name": "test"}, "spec": {"privileged": False},
                "_provenance": {"kubernetes_version": "v1.24.9"}}]}
    _, findings = result(fixture_snapshot(change))
    assert all(f["resource_id"] != "inventory:podsecuritypolicy" for f in findings.values())
    assert any(f["status"] == "PASS" for f in findings.values())
    assert all(f["status"] != "NOT_APPLICABLE" for f in findings.values())


def test_new_resource_check_cannot_inherit_absence(monkeypatch):
    from dataclasses import replace
    original = engine._selection
    candidate = "k8s.ports.podsecuritypolicy.future_resource_check"
    def added(provider, categories, checks, frameworks):
        selected_categories, selected = original(provider, categories, sorted(IDS), frameworks)
        return selected_categories, selected + [replace(selected[0], id=candidate)]
    monkeypatch.setattr(engine, "_selection", added)
    _, findings = result(fixture_snapshot(), IDS | {candidate})
    assert findings[candidate]["status"] == "UNKNOWN"
    assert {findings[c]["status"] for c in IDS} == {"NOT_APPLICABLE"}


def test_general_admission_requirements_keep_own_results():
    ids = {"k8s.cis.psp_binding_enforced", "k8s.cis.admission_privileged", "k8s.cis.admission_hostpath"}
    _, findings = result(fixture_snapshot(), ids)
    assert findings["k8s.cis.admission_privileged"]["status"] == "UNKNOWN"
    assert findings["k8s.cis.admission_hostpath"]["status"] == "UNKNOWN"
    assert all(f["status"] != "PASS" for f in findings.values())
