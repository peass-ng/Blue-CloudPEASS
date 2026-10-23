"""Real-source contracts for the 409 workload/RBAC finding copy corrections."""
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

from peaso.checks import CHECKS
from peaso.checks.k8s_native_review_copy_20261020 import reviewed_fields
from peaso.checks.k8s_workload_clarity_reviewed import ROWS, _digest, description, remediation

PACK = Path(__file__).resolve().parents[1] / "peaso/rulepacks"


@pytest.fixture(scope="module")
def source_rows():
    descriptions = json.loads((PACK / "check_descriptions.json").read_text())["checks"]
    remediations = {}
    for path in PACK.glob("remediation*.json"):
        packed = json.loads(path.read_text())
        if not isinstance(packed, dict):
            continue
        for check_id, row in packed.items():
            if check_id in ROWS and isinstance(row, dict):
                if _digest(row) == ROWS[check_id]["remediation_base_sha256"]:
                    remediations[check_id] = row
    for check_id, row in ROWS.items():
        if row["remediation_base_sha256"] == _digest(None):
            remediations[check_id] = None
    return descriptions, remediations


def test_reviewed_ids_are_exactly_409_registered_checks():
    assert len(ROWS) == 409
    assert set(ROWS) <= {check.id for check in CHECKS}


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_description_preserves_actual_evaluation_contract(check_id, source_rows):
    original = source_rows[0][check_id]
    before = deepcopy(original)
    actual = description(check_id, original)
    assert original == before
    assert actual["description"] == reviewed_fields(check_id, "description", ROWS[check_id]["description_fields"])["description"]
    assert len(actual["description"].split()) <= 40
    updated_fields = reviewed_fields(check_id, "description", ROWS[check_id]["description_fields"])
    assert all(actual[key] == value for key, value in updated_fields.items())
    assert {k: v for k, v in actual.items() if k not in updated_fields} == {
        k: v for k, v in original.items() if k not in updated_fields}


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_remediation_preserves_references_commands_and_bindings(check_id, source_rows):
    original = source_rows[1][check_id]
    before = deepcopy(original)
    actual = remediation(check_id, original)
    assert original == before
    assert 1 <= len(actual["steps"]) <= 2
    assert len(actual["caveats"]) == 1
    assert len(actual["summary"].split()) <= 40
    changed = {"summary", "steps", "caveats"}
    if original is None:
        assert actual["review_status"] == "approved" and actual["cli"] == []
        assert not actual.get("iac") and actual["references"] and actual["field_binding"]
        return
    if original.get("review_status") != "approved":
        assert actual["review_status"] == "approved" and actual["cli"] == []
        assert not actual.get("iac")
        changed |= {"review_status", "cli"}
    assert {k: v for k, v in actual.items() if k not in changed} == {
        k: v for k, v in original.items() if k not in changed}


@pytest.mark.parametrize("check_id", sorted(ROWS))
@pytest.mark.parametrize("kind, apply", [("description", description), ("remediation", remediation)])
def test_stale_source_fails_closed(check_id, kind, apply, source_rows):
    original = deepcopy(source_rows[0 if kind == "description" else 1][check_id])
    if original is None:
        original = {}
    original["description" if kind == "description" else "summary"] = "Unreviewed source changed."
    with pytest.raises(ValueError, match="Reviewed Kubernetes workload clarity base changed"):
        apply(check_id, original)


def test_unowned_check_is_preserved_without_sharing_mutable_state():
    original = {"description": "Keep this exact text.", "evaluated": ["specific.field"]}
    actual = description("unowned.check", original)
    assert actual == original
    actual["evaluated"].append("different")
    assert original["evaluated"] == ["specific.field"]
    assert description("unowned.check", None) is None



@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_every_reviewed_actual_predicate_and_failure_evidence(check_id):
    import inspect
    from peaso.checks.fixtures import CASES
    from peaso.checks.k8s_ports_workloads import KIND_PATHS
    from peaso.checks.k8s_workload_finding_summary import workload_evidence_summary, reviewed_workload_severity
    check = next(check for check in CHECKS if check.id == check_id)
    binding = ROWS[check_id]["reviewed_binding"]
    assert binding["kind"] == check.kind
    assert binding["module"] == check.evaluate.__module__
    captured = inspect.getclosurevars(inspect.unwrap(check.evaluate)).nonlocals
    if check.evaluate.__module__ == "peaso.checks.k8s_ports_workloads":
        assert captured["predicate"] == binding["predicate"]
        assert captured["kind"] == binding["kind"]
        assert binding["pod_spec_path"] == KIND_PATHS[check.kind]
    elif "declared_grants" in binding:
        assert binding["declared_grants"] == captured["function"].__defaults__[0]
    if "source_qualname" in binding:
        assert binding["source_qualname"] == inspect.unwrap(check.evaluate).__qualname__
    cases = CASES.get(check_id)
    # Current native annotation indicators replace caller annotations_complete
    # attestations only for these five admitted IDs; historical CASES stay intact.
    from peaso.checks.k8s_annotation_native_admission_20261020 import IDS as ANNOTATION_IDS
    from peaso.checks import k8s_annotation_native_source_successor_20261021 as annotation_source
    if check_id in ANNOTATION_IDS:
        # The installed successor attests the current collector and reconstructs
        # the exact historical source that these archived cases describe.
        _, native_annotation_cases = sys.modules[annotation_source._PRIVATE_NAME]._reviewed_inputs()
        cases = native_annotation_cases[check_id]
    if cases is None:
        if check_id in ("k8s.rbac.no_wildcards", "k8s.rbac.role_no_wildcards"):
            cases = {"pass": {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
                     "fail": {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}]}}
        elif check_id in ("k8s.rbac.review_broad_subjects", "k8s.rbac.review_namespaced_subjects"):
            cases = {"pass": {"roleRef": {"name": "view"}, "subjects": [{"kind": "User", "name": "alice"}]},
                     "fail": {"roleRef": {"name": "view"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}]}}
        elif check_id == "k8s.pod.no_privileged_containers":
            cases = {"pass": {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": False}}]}},
                     "fail": {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}}}
        elif check_id == "k8s.pod.no_host_namespaces":
            cases = {"pass": {"spec": {"hostNetwork": False}}, "fail": {"spec": {"hostNetwork": True}}}
        elif check_id == "k8s.service.review_public_type":
            cases = {"pass": {"spec": {"type": "ClusterIP"}}, "fail": {"spec": {"type": "NodePort"}}}
        elif check_id in {"k8s_ingress_ingress_has_any_associated_ingress_93579100f9",
                          "k8s_networkpolicy_has_ingress_rules",
                          "k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c",
                          "k8s_pod_secret_pod_rule_non_compliant_fcdc38e543"}:
            from peaso.collectors.k8s import _native
            good_spec, bad_spec = ({"rules": [{}]}, {"rules": []}) if check.kind == "ingress" else (
                ({"imagePullSecrets": [{"name": "registry"}], "containers": [{"name": "app"}]},
                 {"imagePullSecrets": [], "containers": [{"name": "app"}]}) if check.kind == "pod" else
                ({"podSelector": {"matchLabels": {"app": "web"}}}, {"podSelector": {}}) if "podselectors" in check_id else
                ({"ingress": [{}]}, {"ingress": []}))
            cases = {}
            for branch, spec in [("pass", good_spec), ("fail", bad_spec)]:
                row = _native({"kind": {"pod": "Pod", "networkpolicy": "NetworkPolicy", "ingress": "Ingress"}[check.kind], "metadata": {"name": "target", "uid": "target-uid", "namespace": "apps"}, "spec": spec}, check.kind, "fixture", "*", True)
                index = {"context": {"provider": "k8s", "scope": "*", "metadata": {"cluster_id": "fixture"}},
                         "collections": {check.kind: [{"type": check.kind, "scope": "*", "status": "collected", "items": [row]}]},
                         check.kind: [{"type": check.kind, "scope": "*", "provider": "k8s", "data": row}]}
                cases[branch], cases[branch + "_index"] = row, index
        else:
            pytest.fail("Missing reviewed actual predicate fixture: " + check_id)
    for branch, expected in [("pass", "PASS"), ("fail", "FAIL")]:
        fixture_branch = "unknown" if check_id == "k8s.cis.avoid_use_of_system_masters_group" and branch == "pass" else branch
        status, evidence = check.evaluate(deepcopy(cases[fixture_branch]), cases.get(fixture_branch + "_index", cases.get("index", {})))
        if check_id == "k8s.cis.avoid_use_of_system_masters_group" and branch == "pass":
            expected = "UNKNOWN"
        assert status == expected
        finding = {"provider": "k8s", "status": status, "check_id": check_id, "evidence": evidence}
        before = deepcopy(finding)
        if expected == "FAIL":
            assert workload_evidence_summary(finding)
            assert reviewed_workload_severity(finding) in {"info", "low", "medium", "high"}
        else:
            assert workload_evidence_summary(finding) is None
            assert reviewed_workload_severity(finding) is None
        assert finding == before


def test_unknown_evidence_never_claims_a_missing_declaration_or_exposure():
    from peaso.checks.k8s_workload_finding_summary import workload_evidence_summary, reviewed_workload_severity
    for status in ["UNKNOWN", "DENIED", "PASS", "MANUAL"]:
        finding = {"provider": "k8s", "status": status, "check_id": next(iter(ROWS)), "evidence": {}}
        assert workload_evidence_summary(finding) is None
        assert reviewed_workload_severity(finding) is None


def _pod_status(predicate, fields, **pod_fields):
    from peaso.checks.k8s_ports_workloads import evaluate_predicate
    from peaso.checks.facts import Unavailable
    item = {"spec": {"containers": [{"name": "app", "image": "app:v1", **fields}], **pod_fields}}
    try:
        return evaluate_predicate(item, "pod", predicate)[0]
    except Unavailable:
        return "UNKNOWN"


@pytest.mark.parametrize("predicate", ["always_pull", "content_digest_or_always_pull"])
def test_digest_and_kubernetes_pull_defaults_are_not_literal_always_only(predicate):
    digest = "app@sha256:" + "a" * 64
    expected = "FAIL" if predicate == "always_pull" else "PASS"
    assert _pod_status(predicate, {"image": digest, "imagePullPolicy": "IfNotPresent"}) == expected
    assert _pod_status(predicate, {"image": digest, "imagePullPolicy": "Never"}) == "FAIL"
    assert _pod_status(predicate, {"image": "app:latest"}) == expected
    assert _pod_status(predicate, {"image": "app:v2"}) == "FAIL"
    assert _pod_status(predicate, {"image": "app@not-a-valid-digest", "imagePullPolicy": "Always"}) == "UNKNOWN"


def test_version_tag_check_does_not_establish_content_addressing():
    assert _pod_status("pinned_image", {"image": "app:v2"}) == "PASS"
    assert _pod_status("pinned_image", {"image": "app@not-a-validated-digest"}) == "PASS"
    assert _pod_status("pinned_image", {"image": "app:latest"}) == "FAIL"


@pytest.mark.parametrize("resource,group", [("cpu", "limit"), ("cpu", "request"), ("memory", "limit"), ("memory", "request")])
def test_resource_presence_does_not_establish_sufficient_or_positive_capacity(resource, group):
    key = "limits" if group == "limit" else "requests"
    assert _pod_status(resource + "_" + group, {"resources": {key: {resource: "0"}}}) == "PASS"
    assert _pod_status(resource + "_" + group, {"resources": {key: {resource: "bad"}}}) == "UNKNOWN"
    assert _pod_status(resource + "_" + group, {}) == "FAIL"


@pytest.mark.parametrize("predicate,key", [("readiness_probe", "readinessProbe"), ("liveness_probe", "livenessProbe")])
def test_probe_presence_does_not_establish_working_health_check(predicate, key):
    assert _pod_status(predicate, {key: {}}) == "UNKNOWN"
    assert _pod_status(predicate, {key: {"httpGet": {"path": "/health", "port": 8080}}}) == "PASS"
    assert _pod_status(predicate, {key: "not-a-probe"}) == "UNKNOWN"
    assert _pod_status(predicate, {}) == "FAIL"


def test_strict_host_port_profile_flags_zero_without_claiming_reachability():
    assert _pod_status("no_host_ports", {"ports": [{"hostPort": 0}]}) == "FAIL"
    assert _pod_status("no_host_ports", {"ports": [{"containerPort": 443}]}) == "PASS"
    assert _pod_status("no_host_ports", {"ports": [{"hostPort": 65536}]}) == "UNKNOWN"


def test_container_only_nonroot_and_inherited_linux_nonroot_are_separate_contracts():
    from peaso.checks.k8s_extended import _evaluate_pod
    assert _pod_status("declared_nonroot", {}, securityContext={"runAsNonRoot": True}) == "FAIL"
    item = {"spec": {"securityContext": {"runAsNonRoot": True}, "containers": [{"name": "app"}]}}
    assert _evaluate_pod(item, "non_root")[0] == "PASS"
    item["spec"]["containers"][0]["securityContext"] = {"runAsUser": 0}
    assert _evaluate_pod(item, "non_root")[0] == "FAIL"
    item["spec"]["os"] = {"name": "windows"}
    assert _evaluate_pod(item, "non_root")[0] == "NOT_APPLICABLE"


def test_literal_secret_summary_never_contains_values_and_includes_init_ephemeral():
    from peaso.checks.k8s_workload_finding_summary import workload_evidence_summary
    check = next(check for check in CHECKS if check.id == "k8s.claude.pod.no_literal_secret_env")
    item = {"spec": {"containers": [{"name": "app"}], "ephemeralContainers": [{"name": "debug", "env": [{"name": "API_KEY", "value": "NEVER_RENDER_THIS_SECRET"}]}]}}
    status, evidence = check.evaluate(item, {})
    assert status == "FAIL"
    summary = workload_evidence_summary({"provider": "k8s", "check_id": check.id, "status": status, "evidence": evidence})
    assert "API_KEY" in summary and "debug" in summary
    assert "NEVER_RENDER_THIS_SECRET" not in summary


def test_reviewed_source_severity_is_explicit_and_fail_closed():
    from peaso.checks.k8s_workload_clarity_reviewed import REVIEWED_RISKS, severity_review
    checks = {check.id:check for check in CHECKS}
    assert set(REVIEWED_RISKS) == set(ROWS)
    for check_id,row in ROWS.items():
        assert row['reviewed_source_severity'] == checks[check_id].severity
        assert severity_review(check_id,checks[check_id].severity) == row['reviewed_severity']
        with pytest.raises(ValueError,match='source severity changed'):
            severity_review(check_id,'unreviewed severity')
