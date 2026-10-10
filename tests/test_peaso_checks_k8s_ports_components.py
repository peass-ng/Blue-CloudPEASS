"""Component flag truth fixtures and safe metadata projection acceptance."""
import copy
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks import k8s_ports_components as ports
from peaso.checks.fixtures import CASES
from peaso.collectors.k8s import _sanitize

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_modeled_available_settings_and_actual_gaps_are_distinct(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    original = copy.deepcopy(item)
    actual, evidence = REGISTRY[cid].evaluate(item, {})
    assert actual == wanted, evidence
    assert item == original


def sample_config(component="kube-apiserver", flags=None, **extra):
    return {"spec": {"containers": [{"name": "component", "_component_config": {
        "component": component, "flags_complete": True, "flags": flags or {}, **extra}}]}}


def test_only_approved_configuration_fields_survive_projection():
    value = {"command": ["kube-apiserver", "--authorization-mode=Node,RBAC", "--private-token=INERT_PRIVATE_MARKER"],
             "args": ["--profiling", "false", "--tls-private-key-file=/etc/tls/private.key"]}
    scrubbed = _sanitize(value)
    assert "INERT_PRIVATE_MARKER" not in json.dumps(scrubbed)
    assert scrubbed["command_redacted"] and scrubbed["args_redacted"]
    assert scrubbed["_component_config"]["flags"] == {"authorization-mode": "Node,RBAC", "profiling": "false",
                                                   "tls-private-key-file": "/etc/tls/private.key"}


def test_projection_rejects_shell_text_uri_credentials_and_duplicate_flags():
    for command in [["kube-apiserver", "--audit-log-path=secret with spaces"],
                    ["kube-apiserver", "--audit-log-path=https://user:password@example.org"],
                    ["kube-apiserver", "--profiling=false", "--profiling=true"]]:
        assert _sanitize({"command": command})["_component_config"]["collection_status"] == "malformed"


def test_known_component_absence_is_not_a_safe_default():
    check = REGISTRY["k8s.ports.pod.container_argument_authorization_mode_rbac"]
    assert check.evaluate(sample_config(flags={}), {})[0] == "UNKNOWN"
    assert check.evaluate(sample_config(component="etcd", flags={"client-cert-auth": "true"}), {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"spec": {"containers": [{"name": "app"}]}}, {})[0] == "UNKNOWN"


def test_component_property_denial_and_incomplete_projection_remain_unknown():
    check = REGISTRY["k8s.ports.pod.container_argument_authorization_mode_rbac"]
    item = sample_config(flags={"authorization-mode": "RBAC"}, flags_complete=False)
    assert check.evaluate(item, {})[0] == "UNKNOWN"
    item = sample_config(flags={"authorization-mode": "RBAC", "_coverage": {"authorization-mode": {"status": "denied"}}})
    assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_legacy_psp_is_version_bounded_and_not_admission_enforcement_proof():
    check = REGISTRY["k8s.ports.pod.container_argument_pod_security_policy_enabled"]
    assert check.evaluate(sample_config(flags={"enable-admission-plugins": "PodSecurityPolicy"}, version="v1.24.0"), {})[0] == "PASS"
    assert check.evaluate(sample_config(flags={"enable-admission-plugins": "PodSecurityPolicy"}, version="v1.25.0"), {})[0] == "NOT_APPLICABLE"
    assert check.evaluate(sample_config(flags={"enable-admission-plugins": "PodSecurityPolicy"}), {})[0] == "UNKNOWN"


def test_multi_plugin_declaration_has_true_membership_not_singleton_argv_match():
    check = REGISTRY["k8s.ports.pod.container_argument_node_restriction_enabled"]
    assert check.evaluate(sample_config(flags={"enable-admission-plugins": "NamespaceLifecycle,NodeRestriction,ServiceAccount"}), {})[0] == "PASS"
    # Pinned query literal singleton element is absent in this valid argv.
    assert "--enable-admission-plugins=NodeRestriction" not in ["--enable-admission-plugins=NamespaceLifecycle,NodeRestriction,ServiceAccount"]


def test_audit_path_and_pem_extension_rejection_counterexamples():
    check = REGISTRY["k8s.ports.pod.container_argument_audit_log_path_configured"]
    assert check.evaluate(sample_config(flags={"audit-log-path": "/var/log/audit.log"}), {})[0] == "PASS"
    # Source Pod CASE has ELSE alarm even when its missing-path condition is false.
    reference_has_path = "--audit-log-path=/var/log/audit.log"
    assert "--audit-log-path=" in reference_has_path
    ca = REGISTRY["k8s.ports.pod.container_argument_kube_controller_manager_root_ca_file_configured"]
    assert ca.evaluate(sample_config(component="kube-controller-manager", flags={"root-ca-file": "/etc/pki/root-ca.crt"}), {})[0] == "PASS"
    assert "pem" not in "/etc/pki/root-ca.crt"


def test_numeric_threshold_boundaries_match_reviewed_case_conditions():
    check = REGISTRY["k8s.ports.pod.container_argument_audit_log_maxage_greater_than_30"]
    for value, expected in [("29", "FAIL"), ("30", "PASS"), ("31", "PASS"), ("thirty", "UNKNOWN")]:
        assert check.evaluate(sample_config(flags={"audit-log-maxage": value}), {})[0] == expected


def test_component_shard_does_not_overlap_workload_partition():
    root = Path(__file__).resolve().parents[1] / "peaso/rulepacks"
    own = json.loads((root / "reviewed_k8s_ports_components.json").read_text())
    workload = json.loads((root / "reviewed_k8s_ports_workloads.json").read_text())
    assert len(own) > 400
    assert not set(own).intersection(workload)
    assert all(row["reason"] and row["official_docs"] and row["review_notes"]["revision"] for row in own.values())
