"""Directed literal-key coverage checks for registered defensive predicates."""
from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks.claude_aws_b_db import INST_ARN
from peaso.checks.compliance_new_sw25_facts import IDS


def _marked(item, key, marker):
    row = copy.deepcopy(item)
    row["_coverage"] = {key: marker}
    return row


@pytest.mark.parametrize("marker, expected", [
    (None, "UNKNOWN"), ({"status": "empty"}, "UNKNOWN"),
    ({"status": "denied"}, "UNKNOWN"), ({"status": "collected"}, "PASS"),
])
def test_rds_dotted_parameter_coverage(marker, expected):
    item = {"DBInstanceArn": INST_ARN, "Engine": "postgres",
            "ParameterGroupValues": _marked({"rds.force_ssl": "1"}, "rds.force_ssl", marker)}
    assert evaluate_check("aws.cb.rds.instance_tls_parameters", item)[0] == expected
    if marker is None:
        item["ParameterGroupValues"].pop("_coverage")
        assert evaluate_check("aws.cb.rds.instance_tls_parameters", item)[0] == "PASS"


@pytest.mark.parametrize("marker, expected", [
    (None, "UNKNOWN"), ({"status": "empty"}, "UNKNOWN"),
    ({"status": "denied"}, "UNKNOWN"), ({"status": "collected"}, "PASS"),
])
def test_gcp_optional_selected_coverage(marker, expected):
    item = _marked({"name": "projects/p/topics/t", "kmsKeyName": "key",
                    "_provenance": {"representation": "full"}}, "kmsKeyName", marker)
    assert evaluate_check("gcp_pubsub_topic_cmek", item)[0] == expected
    if marker is None:
        item.pop("kmsKeyName")
        item.pop("_coverage")
        assert evaluate_check("gcp_pubsub_topic_cmek", item)[0] == "FAIL"


def test_aws_optional_omission_rejects_null_marker():
    item = {"logGroupName": "audit", "_provenance": {
        "operation": "logs:DescribeLogGroups", "native_response_complete": True}}
    assert evaluate_check("aws.a.cloudwatch.log_kms_encryption", item)[0] == "FAIL"
    for marker, expected in ((None, "UNKNOWN"), ({"status": "denied"}, "UNKNOWN"),
                             ({"status": "empty"}, "FAIL")):
        assert evaluate_check("aws.a.cloudwatch.log_kms_encryption",
                              _marked(item, "kmsKeyId", marker))[0] == expected


def test_sw25_literal_annotation_coverage():
    # The signed draft registers IDs already present in the published registry.
    # Import its existing fixture with those entries temporarily removed.
    saved = list(CHECKS)
    try:
        CHECKS[:] = [check for check in CHECKS if check.id not in IDS]
        sys.path.insert(0, str(Path(__file__).parent))
        draft = importlib.import_module("test_peaso_compliance_new_sw25")
    finally:
        CHECKS[:] = saved
    def case(marker):
        index = draft.fixture(draft.sw.APPARMOR_ID)
        draft.data(index, "pod_runtime")["appArmorNodeEvidence"]["kubernetesVersion"] = "v1.29.0"
        pod = draft.data(index, "pod")
        annotations = {}
        for kind in ("containers", "initContainers", "ephemeralContainers"):
            container = pod["spec"][kind][0]
            container.pop("securityContext")
            annotations["container.apparmor.security.beta.kubernetes.io/" + container["name"]] = "runtime/default"
        key = "container.apparmor.security.beta.kubernetes.io/main"
        if marker != "absent":
            annotations["_coverage"] = {key: marker}
        pod["metadata"]["annotations"] = annotations
        return draft.evaluate(draft.sw.APPARMOR_ID, index)[0]
    assert case("absent") == "PASS"
    assert case({"status": "collected"}) == "PASS"
    assert case(None) == "UNKNOWN"
    assert case({"status": "denied"}) == "UNKNOWN"
    assert case({"status": "empty"}) == "UNKNOWN"
