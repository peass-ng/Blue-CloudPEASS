from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.k8s_component_finding_summary import component_evidence_summary
from peaso.checks.k8s_finding_clarity_reviewed import ROWS


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_real_failure_evidence_has_brief_specific_declaration_summary(check_id):
    check = next(check for check in CHECKS if check.id == check_id)
    status, evidence = check.evaluate(deepcopy(CASES[check_id]["fail"]), {})
    finding = {"provider": "k8s", "check_id": check_id, "status": status, "evidence": evidence}
    before = deepcopy(finding)
    text = component_evidence_summary(finding)
    assert text and "Container “component” declares " in text
    assert "_component_config" not in text
    assert "observations" not in text
    assert len(text) < 360
    assert finding == before


@pytest.mark.parametrize("status", ["UNKNOWN", "PASS", "MANUAL", "DENIED"])
def test_missing_context_is_not_presented_as_observed_failure(status):
    assert component_evidence_summary({"provider": "k8s", "check_id": next(iter(ROWS)),
                                       "status": status, "evidence": {}}) is None


def test_empty_certificate_path_does_not_claim_self_signed_tls():
    cid = "k8s.ports.pod.container_argument_kubelet_tls_cert_file_and_tls_private_key_file_configured"
    check = next(check for check in CHECKS if check.id == cid)
    status, evidence = check.evaluate(deepcopy(CASES[cid]["fail"]), {})
    text = component_evidence_summary({"provider": "k8s", "check_id": cid, "status": status, "evidence": evidence})
    assert "empty TLS certificate path and TLS private-key path" in text
    assert "self-signed" not in text and "unencrypted" not in text


def test_wrong_component_missing_field_and_unreviewed_id_fall_back():
    cid = "k8s.ports.pod.container_argument_authorization_mode_no_always_allow"
    item = {"provider": "k8s", "check_id": cid, "status": "FAIL", "evidence": {
        "containers_needing_review": ["api"], "observations": [{"container": "api", "component": "etcd", "settings": {"authorization-mode": "AlwaysAllow"}}]}}
    assert component_evidence_summary(item) is None
    item["evidence"]["observations"][0]["component"] = "kube-apiserver"
    assert "authorization mode=AlwaysAllow" in component_evidence_summary(item)
    item["evidence"]["observations"][0]["settings"] = {}
    assert component_evidence_summary(item) is None
    item["check_id"] = "k8s.unreviewed.check"
    assert component_evidence_summary(item) is None
