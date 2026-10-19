"""Real-source contracts for the 509 reviewed Kubernetes declaration descriptions."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks.k8s_finding_clarity_reviewed import ROWS, _digest, description, remediation

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
    return descriptions, remediations


def test_reviewed_ids_are_exactly_509_registered_checks():
    assert len(ROWS) == 509
    assert set(ROWS) <= {check.id for check in CHECKS}


@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_description_preserves_actual_evaluation_contract(check_id, source_rows):
    original = source_rows[0][check_id]
    before = deepcopy(original)
    actual = description(check_id, original)
    assert original == before
    assert actual["description"] == ROWS[check_id]["description_fields"]["description"]
    assert len(actual["description"].split()) <= 40
    assert {k: v for k, v in actual.items() if k != "description"} == {
        k: v for k, v in original.items() if k != "description"}


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
    if original["review_status"] == "field_derived_reference_pending":
        changed |= {"review_status", "cli"}
        assert actual["review_status"] == "approved"
        assert actual["cli"] == []
        assert not actual.get("iac")
        assert actual["references"] == original["references"]
        assert actual["field_binding"] == original["field_binding"]
    assert {k: v for k, v in actual.items() if k not in changed} == {
        k: v for k, v in original.items() if k not in changed}


@pytest.mark.parametrize("check_id", sorted(ROWS))
@pytest.mark.parametrize("kind, apply", [("description", description), ("remediation", remediation)])
def test_stale_source_fails_closed(check_id, kind, apply, source_rows):
    original = deepcopy(source_rows[0 if kind == "description" else 1][check_id])
    original["description" if kind == "description" else "summary"] = "Unreviewed source changed."
    with pytest.raises(ValueError, match="Reviewed Kubernetes clarity base changed"):
        apply(check_id, original)


def test_unowned_check_is_preserved_without_sharing_mutable_state():
    original = {"description": "Keep this exact text.", "evaluated": ["specific.field"]}
    actual = description("unowned.check", original)
    assert actual == original
    actual["evaluated"].append("different")
    assert original["evaluated"] == ["specific.field"]
    assert description("unowned.check", None) is None



@pytest.mark.parametrize("check_id", sorted(ROWS))
def test_exact_kind_component_comparison_and_declaration_scope(check_id):
    from peaso.checks.fixtures import CASES
    import inspect
    from peaso.checks.k8s_ports_workloads import KIND_PATHS
    from peaso.checks.facts import get
    check = next(check for check in CHECKS if check.id == check_id)
    binding = ROWS[check_id]["reviewed_binding"]
    suffix = check_id.split(".", 3)[3]
    captured = inspect.getclosurevars(inspect.unwrap(check.evaluate)).nonlocals
    assert captured["kind"] == check.kind
    component, fields, operation, expected, _ = captured["spec"]
    normalize = lambda value: sorted(value) if isinstance(value, (set, frozenset)) else list(value) if isinstance(value, tuple) else value
    assert binding == {"kind": check.kind, "pod_spec_path": KIND_PATHS[check.kind],
                       "component": normalize(component), "fields": fields,
                       "operation": operation, "expected": normalize(expected)}
    for branch, expected_status in [("pass", "PASS"), ("fail", "FAIL")]:
        item = deepcopy(CASES[check_id][branch])
        assert check.evaluate(item, {})[0] == expected_status
    item = deepcopy(CASES[check_id]["pass"])
    pod = get(item, binding["pod_spec_path"], dict)
    flags = pod["containers"][0]["_component_config"]["flags"]
    for field in fields:
        flags.pop(field, None)
    assert check.evaluate(item, {})[0] == ("PASS" if operation == "absent" else "UNKNOWN")
    item = deepcopy(CASES[check_id]["pass"])
    pod = get(item, binding["pod_spec_path"], dict)
    pod["containers"][0]["_component_config"]["component"] = "etcd" if "kube-scheduler" in ((component,) if isinstance(component, str) else component) else "kube-scheduler"
    assert check.evaluate(item, {})[0] == "NOT_APPLICABLE"


def test_declarations_do_not_make_effective_runtime_claims():
    encryption = next(row for cid, row in ROWS.items() if "encryption_providers" in cid)
    assert "nonempty encryption-provider-config path" in encryption["description_fields"]["description"]
    assert "does not establish" in encryption["remediation_fields"]["caveats"][0]
    for check_id, row in ROWS.items():
        assert "captured" in row["description_fields"]["description"]
        assert "self-signed" not in row["description_fields"]["description"]
        assert "Secrets are stored" not in row["description_fields"]["description"]


@pytest.mark.parametrize("operation,fields,expected,flags,wanted", [
    ("gt", ["secure-port"], 0, {"secure-port": "0"}, False),
    ("gt", ["secure-port"], 0, {"secure-port": "1"}, True),
    ("gt", ["secure-port"], 0, {"secure-port": "-1"}, None),
    ("gt", ["secure-port"], 0, {"secure-port": "65536"}, True),
    ("nonzero_duration", ["streaming-connection-idle-timeout"], None,
     {"streaming-connection-idle-timeout": "0s"}, False),
    ("nonzero_duration", ["streaming-connection-idle-timeout"], None,
     {"streaming-connection-idle-timeout": "-1s"}, None),
    ("nonzero_duration", ["streaming-connection-idle-timeout"], None,
     {"streaming-connection-idle-timeout": "1m"}, True),
    ("nonzero_duration", ["streaming-connection-idle-timeout"], None,
     {"streaming-connection-idle-timeout": "unavailable"}, None),
    ("contains", ["authorization-mode"], "RBAC", {"authorization-mode": "Node,RBAC"}, True),
    ("contains", ["authorization-mode"], "RBAC", {"authorization-mode": "Node, RBAC"}, False),
    ("contains", ["authorization-mode"], "Node", {"authorization-mode": "NodeRestriction"}, False),
    ("present", ["cert-file", "key-file"], None, {"cert-file": "/cert", "key-file": ""}, False),
    ("equal", ["client-cert-auth"], "true", {"client-cert-auth": True}, None),
])
def test_family_comparison_boundaries_are_not_runtime_inferences(operation, fields, expected, flags, wanted):
    from peaso.checks.facts import Unavailable
    from peaso.checks.k8s_ports_components import compare
    if wanted is None:
        with pytest.raises(Unavailable):
            compare(flags, fields, operation, expected)
    else:
        assert compare(flags, fields, operation, expected) is wanted


@pytest.mark.parametrize("check_id", [cid for cid in sorted(ROWS) if
    "pod_security_policy_enabled" in cid or "security_context_deny_enabled" in cid])
def test_legacy_admission_version_boundaries_never_enable_removed_plugins(check_id, source_rows):
    from peaso.checks.fixtures import CASES
    from peaso.checks.facts import get
    check = next(check for check in CHECKS if check.id == check_id)
    item = deepcopy(CASES[check_id]["fail"])
    config = get(item, ROWS[check_id]["reviewed_binding"]["pod_spec_path"], dict)["containers"][0]["_component_config"]
    config["version"] = "v1.24.9"
    assert check.evaluate(item, {})[0] == "FAIL"
    config.pop("version")
    assert check.evaluate(item, {})[0] == "UNKNOWN"
    config["version"] = "v1.30.0"
    assert check.evaluate(item, {})[0] == "NOT_APPLICABLE"
    actual = remediation(check_id, source_rows[1][check_id])
    assert actual["cli"] == []
    assert "legacy cluster" in actual["summary"]
    if "pod_security_policy_enabled" in check_id:
        config["version"] = "v1.25.0"
        assert check.evaluate(item, {})[0] == "NOT_APPLICABLE"
        assert "only through Kubernetes 1.24" in actual["caveats"][0]
    else:
        config["version"] = "v1.25.0"
        config["flags"]["enable-admission-plugins"] = "PodSecurityPolicy"
        assert check.evaluate(item, {})[0] == "FAIL"
        config["flags"]["enable-admission-plugins"] = "SecurityContextDeny"
        assert check.evaluate(item, {})[0] == "PASS"
        assert "1.25–1.29 require SecurityContextDeny" in actual["caveats"][0]


def test_reviewed_source_severity_is_explicit_and_fail_closed():
    from peaso.checks.k8s_finding_clarity_reviewed import REVIEWED_RISKS, severity_review
    checks = {check.id:check for check in CHECKS}
    assert set(REVIEWED_RISKS) == set(ROWS)
    for check_id,row in ROWS.items():
        assert row['reviewed_source_severity'] == checks[check_id].severity
        assert severity_review(check_id,checks[check_id].severity) == 'medium'
        with pytest.raises(ValueError,match='source severity changed'):
            severity_review(check_id,'unreviewed severity')
