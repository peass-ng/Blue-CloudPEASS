"""Run against an isolated wheel installation, outside the checkout, with no network."""
import json
import os
from pathlib import Path
import socket
import sys

installation = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(installation))
os.chdir("/tmp")


def forbidden(*args, **kwargs):
    raise AssertionError("offline installed evaluator attempted network I/O")


socket.socket.connect = forbidden
socket.create_connection = forbidden
import peaso
from peaso.demo import demo_snapshot
from peaso.engine import evaluate_snapshot
from peaso.analysis.iam import permission_severity
from scripts.cloud_permission_risks import _bundled_rules_path
from bluepeass.k8s_risks import _rules_path
assert str(Path(peaso.__file__).resolve()).startswith(str(installation))
classifications = {}
for provider, permission in [("aws", "iam:PutRolePolicy"), ("gcp", "iam.serviceAccountKeys.create"), ("azure", "Microsoft.Authorization/roleAssignments/write")]:
    path = _bundled_rules_path(provider)
    assert path.is_file() and str(path.resolve()).startswith(str(installation))
    classifications[provider] = permission_severity(provider, permission)
    assert classifications[provider] == "critical"
assert _rules_path().is_file() and _rules_path().parent.joinpath("hacktricks-source.json").is_file()
reports = {}
for provider in ("aws", "gcp", "azure", "k8s"):
    report = evaluate_snapshot(demo_snapshot(provider))
    assert report["findings"]
    reports[provider] = {"resources": report["stats"]["resource_count"], "findings": report["stats"]["finding_count"]}
print(json.dumps({"installed_outside_checkout": True, "network_calls": 0,
    "bundled_providers": ["aws", "gcp", "azure", "k8s"], "representative_classification": classifications, "offline_reports": reports}, indent=2))
