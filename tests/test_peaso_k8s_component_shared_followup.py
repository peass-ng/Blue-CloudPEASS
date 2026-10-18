"""Registered component controls preserve confirmed-empty projection semantics."""
import copy

import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import k8s_ports_components as components


CHECK_BY_ID = {check.id: check for check in CHECKS}
ABSENT = "k8s.ports.pod.container_no_argument_basic_auth_file"
PRESENT = "k8s.ports.pod.container_argument_audit_log_path_configured"


def declared(check_id):
    check = CHECK_BY_ID[check_id]
    item = copy.deepcopy(CASES[check_id]["pass"])
    _, containers = components.pod_spec(item, check.kind)
    assert len(containers) == 1
    return check, item, containers[0]["_component_config"]


@pytest.mark.parametrize("value,wanted", [(None, "PASS"), ("", "FAIL")])
def test_confirmed_empty_forbidden_flag_preserves_absence_or_measured_failure(value, wanted):
    check, item, config = declared(ABSENT)
    config["flags"]["_coverage"] = {"basic-auth-file": {"status": "empty"}}
    if value is not None:
        config["flags"]["basic-auth-file"] = value
    assert check.evaluate(item, {})[0] == wanted


def test_confirmed_empty_required_flag_is_measured_failure():
    check, item, config = declared(PRESENT)
    config["flags"]["audit-log-path"] = ""
    config["flags"]["_coverage"] = {"audit-log-path": {"status": "empty"}}
    assert check.evaluate(item, {})[0] == "FAIL"


def test_confirmed_empty_flags_map_keeps_complete_absence():
    check, item, config = declared(ABSENT)
    config["_coverage"] = {"flags": {"status": "empty"}}
    assert check.evaluate(item, {})[0] == "PASS"


@pytest.mark.parametrize("marker", [None, "malformed", {"status": "denied"}, {"status": "collected"}])
def test_explicit_unusable_or_contradictory_missing_flag_coverage_is_unknown(marker):
    check, item, config = declared(ABSENT)
    config["flags"]["_coverage"] = {"basic-auth-file": marker}
    assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_empty_coverage_with_nonempty_forbidden_flag_is_contradictory():
    check, item, config = declared(ABSENT)
    config["flags"].update({"basic-auth-file": "/etc/auth.csv", "_coverage": {"basic-auth-file": {"status": "empty"}}})
    assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_collected_forbidden_flag_keeps_independent_measured_failure():
    check, item, config = declared(ABSENT)
    config["flags"].update({"basic-auth-file": "/etc/auth.csv", "_coverage": {"basic-auth-file": {"status": "collected"}}})
    assert check.evaluate(item, {})[0] == "FAIL"


def test_complete_genuine_omission_keeps_version_bounded_default():
    check, item, config = declared(ABSENT)
    assert config["flags"] == {}
    assert check.evaluate(item, {})[0] == "PASS"
    config["version"] = "v1.19.0"
    assert check.evaluate(item, {})[0] == "NOT_APPLICABLE"
