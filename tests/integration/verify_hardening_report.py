"""Verify live reports without retaining cloud identities or findings in Git.

Usage: python tests/integration/verify_hardening_report.py /private/report-dir
The directory should contain aws.json, gcp.json, azure.json, and k8s.json.
"""

import collections
import json
from pathlib import Path
import sys


def verify(directory):
    expected = {"aws": {"aws-compliance": 679, "aws-perimeter": 62},
                "azure": {"azure-compliance": 476, "azure-perimeter": 14},
                "gcp": {"gcp-compliance": 202, "gcp-perimeter": 33},
                "k8s": {"kubernetes-compliance": 769}}
    for provider, counts in expected.items():
        report = json.loads((directory / (provider + ".json")).read_text())
        audits = [target["data"]["hardening"] for target in report["targets"] if "hardening" in target.get("data", {})]
        assert audits, provider + ": no hardening target"
        for audit in audits:
            assert dict(collections.Counter(c["suite"] for c in audit["controls"])) == counts, provider + ": some suites/controls were not attempted"
            assert audit["findings"], provider + ": no resource findings"
            assert not any("relation " in e["error"] and "does not exist" in e["error"] for e in audit["errors"]), provider + ": missing connection schema"
            assert not any("credential cannot be nil" in e["error"] or "no valid token for audience" in e["error"] for e in audit["errors"]), provider + ": credential adapter failure"
            if provider == "k8s":
                assert not audit["errors"], "Unexpected Kubernetes execution error"
                for control in ["deployment_container_privilege_disabled", "deployment_non_root_container", "deployment_immutable_container_filesystem"]:
                    statuses = {f["dimensions"].get("deployment_name"): f["status"] for f in audit["findings"] if f["control_id"].endswith("." + control)}
                    assert statuses["needs-hardening"] == "FAIL", control
                    assert statuses["hardened"] == "PASS", control
                excluded = audit["coverage"]["excluded_controls"]
                assert any(c["control_id"].endswith(".secret_default_namespace_used") for c in excluded)
            print(provider + ": " + json.dumps(audit["summary"]))


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
