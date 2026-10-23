"""Observed privilege-path copy stays tied to the recorded GCP path."""

import pytest

from peaso import privesc
from peaso.privesc.gcp_observed_impact import evidence_summary


IDS = (
    "gcp-workflows-create-actas-execute",
    "gcp-workflows-create-cross-project-actas",
    "gcp-workflows-update-actas",
    "gcp-workflows-update-source-retain-sa",
    "gcp-workflows-update-source-await-execution",
    "gcp-workstations-config-create-actas",
    "gcp-workstations-config-update-code",
    "gcp-workstations-use-existing-workstation",
    "gcp-workstations-create-from-existing-config",
)
ENTRIES = {entry["id"]: entry for entry in privesc.catalog()["entries"]}


def finding(cid, confidence):
    status = {"derived": "FAIL", "conditional": "MANUAL", "unknown": "UNKNOWN"}[confidence]
    missing = confidence == "unknown"
    return {
        "provider": "gcp", "category": "privesc", "check_id": cid, "status": status,
        "evidence": {
            "technique": {"id": cid, "source": ENTRIES[cid]["source"]},
            "source": {"id": "user:dev@example.com", "label": "dev@example.com"},
            "targets": [{"id": "serviceAccount:worker@example.com", "label": "worker@example.com",
                         "type": "gcp_service_account", **({"underlying_count": 0} if missing else {})}],
            "target_count": 0 if missing else 1,
            "confidence": confidence,
            "conditions": ["target_account_unresolved"] if missing else [],
            "granting_permissions": [] if missing else [{"permission": "recorded.permission"}],
            "granting_statements": [],
        },
    }


@pytest.mark.parametrize("cid", IDS)
@pytest.mark.parametrize("confidence", ("derived", "conditional", "unknown"))
def test_each_active_path_has_three_recorded_plain_lines(cid, confidence):
    text = evidence_summary(finding(cid, confidence))
    assert text is not None
    lines = text.splitlines()
    assert len(lines) == 3
    assert all(line.endswith(".") and "\n" not in line for line in lines)
    assert "dev@example.com" in lines[0]
    assert "may" in lines[1] or "could" in lines[1]
    assert "could" in lines[2] and "data" in lines[2]
    assert "check" not in text.lower() and "scan" not in text.lower()
    if confidence == "unknown":
        assert "not fully recorded" in lines[0]
        assert "target account" in lines[0]
    else:
        assert "recorded" in lines[0] and "worker@example.com" in lines[0]


@pytest.mark.parametrize("cid", IDS)
def test_copy_rejects_unvalidated_path_evidence(cid):
    row = finding(cid, "derived")
    row["evidence"]["granting_permissions"] = []
    assert evidence_summary(row) is None
