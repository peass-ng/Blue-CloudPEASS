"""Directed pure tests for native SecurityIncident history projection."""
import copy

import pytest

from peaso.collectors.azure_wave_logging_native import project


WORKSPACE = "11111111-1111-1111-1111-111111111111"
NAME = "incident-1"


def fixture():
    proof = {"source_operation": "logs.query.SecurityIncident", "read_only": True,
             "complete": True, "workspace_id": WORKSPACE,
             "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-02T00:00:00Z",
             "retention_source_operation": "operationalinsights.tables.get",
             "retention_observed_at": "2026-10-02T00:00:00Z", "analytics_retention_days": 30}
    first = {"Type": "SecurityIncident", "TenantId": WORKSPACE, "IncidentName": NAME,
             "TimeGenerated": "2026-10-01T00:01:00Z", "CreatedTime": "2026-10-01T00:00:30Z",
             "LastModifiedTime": "2026-10-01T00:00:30Z", "Status": "New", "Tasks": []}
    second = {**first, "TimeGenerated": "2026-10-01T01:01:00Z",
              "LastModifiedTime": "2026-10-01T01:00:00Z", "Status": "Active",
              "Tasks": [{"taskId": "task-1", "status": "New",
                         "lastModifiedTimeUtc": "2026-10-01T00:59:00Z"}]}
    third = copy.deepcopy(second)
    third["TimeGenerated"] = "2026-10-01T02:01:00Z"
    third["LastModifiedTime"] = "2026-10-01T02:00:00Z"
    third["Tasks"][0]["status"] = "Completed"
    third["Tasks"][0]["lastModifiedTimeUtc"] = "2026-10-01T01:59:00Z"
    return [first, second, third], proof


def test_observed_history_never_claims_triage_or_procedure():
    rows, proof = fixture()
    result = project(NAME, rows, proof)
    assert result["baseline_status"] == "New"
    assert [x["to"] for x in result["observed_status_transitions"]] == ["Active"]
    assert result["observed_status_transitions"][0]["seen_by"] == "2026-10-01T01:01:00+00:00"
    assert result["observed_task_transitions"][0]["to"] == "Completed"
    assert result["triageHistoryComplete"] is False
    assert result["responseProcess"] == "not_collected"


@pytest.mark.parametrize("change,reason", [
    (lambda rows, proof: proof.update(complete=False), "query incomplete"),
    (lambda rows, proof: proof.update(analytics_retention_days=0), "retention"),
    (lambda rows, proof: proof.update(retention_source_operation="operator_review"), "native table retention"),
    (lambda rows, proof: rows[1].update(TenantId="22222222-2222-2222-2222-222222222222"), "foreign"),
    (lambda rows, proof: rows[1].update(TimeGenerated=rows[0]["TimeGenerated"]), "chronology"),
    (lambda rows, proof: rows[1].update(Tasks=None), "task state unavailable"),
    (lambda rows, proof: rows[1]["Tasks"].append(copy.deepcopy(rows[1]["Tasks"][0])), "duplicate"),
])
def test_rejects_unsupported_history_claims(change, reason):
    rows, proof = fixture()
    change(rows, proof)
    with pytest.raises(ValueError, match=reason):
        project(NAME, rows, proof)
