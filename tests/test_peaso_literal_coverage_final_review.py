"""One registered SW25 AppArmor literal-coverage regression."""
from __future__ import annotations

import importlib.util
from pathlib import Path

from peaso.checks import CHECKS, evaluate_check
from peaso.checks.compliance_new_sw25_facts import APPARMOR_ID
from tests.compliance_draft_isolation import staged_registry


def test_registered_apparmor_annotation_coverage():
    # Load the signed local fixture without its duplicate draft registrations.
    registered = next(check for check in CHECKS if check.id == APPARMOR_ID)
    path = Path(__file__).with_name("test_peaso_compliance_new_sw25.py")
    spec = importlib.util.spec_from_file_location("_sw25_final_review_fixture", path)
    fixture = importlib.util.module_from_spec(spec)
    with staged_registry(("compliance_new_sw25",)):
        spec.loader.exec_module(fixture)
    assert next(check for check in CHECKS if check.id == APPARMOR_ID) is registered

    key = "container.apparmor.security.beta.kubernetes.io/main"
    for marker, expected in (("absent", "PASS"), ({"status": "collected"}, "PASS"),
                             (None, "UNKNOWN"), ("malformed", "UNKNOWN"),
                             ({"status": "denied"}, "UNKNOWN"),
                             ({"status": "empty"}, "UNKNOWN")):
        index = fixture.fixture(APPARMOR_ID)
        fixture.data(index, "pod_runtime")["appArmorNodeEvidence"]["kubernetesVersion"] = "v1.29.0"
        pod = fixture.data(index, "pod")
        annotations = {}
        for kind in ("containers", "initContainers", "ephemeralContainers"):
            container = pod["spec"][kind][0]
            container.pop("securityContext")
            annotations["container.apparmor.security.beta.kubernetes.io/" + container["name"]] = "runtime/default"
        if marker != "absent":
            annotations["_coverage"] = {key: marker}
        pod["metadata"]["annotations"] = annotations
        assert evaluate_check(APPARMOR_ID, {"scope": fixture.SCOPE}, index)[0] == expected
