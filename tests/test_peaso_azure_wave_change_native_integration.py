"""Directed public evaluator regressions for native Activity Log coverage."""
from copy import deepcopy

from peaso.checks import evaluate_check


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
RESOURCE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Web/sites/app"
START = "2026-10-01T00:00:00Z"
END = "2026-10-10T00:00:00Z"
WHEN = "2026-10-05T00:00:00Z"


def _index(cid, policy, rows):
    collections = {}
    wrappers = {}
    for kind, values in rows.items():
        collections[kind] = [{"type": kind, "scope": SCOPE,
                              "status": "collected" if values else "empty", "items": values}]
        wrappers[kind] = [{"type": kind, "scope": SCOPE, "data": value} for value in values]
    collections["activity_log"][0]["queryWindow"] = {
        "start": START, "end": END, "endExclusive": True,
    }
    wave = "sw33" if cid == "azure.other.change_approval_trace" else "sw26"
    key = "changeApproval" if wave == "sw33" else cid
    return {"context": {"provider": "azure", "scope": SCOPE,
                         "created_at": "2026-10-12T00:00:00Z",
                         "metadata": {"compliance_policy": {wave: {
                             "status": "collected", "scope": SCOPE, key: policy}}}},
            "collections": collections, **wrappers}


def _case(cid):
    activity = {"id": "azure-activity://event-1", "resourceId": RESOURCE,
                "correlationId": "corr", "caller": "principal-1",
                "operationName": {"value": "Microsoft.Web/sites/write"},
                "status": {"value": "Succeeded"}, "eventTimestamp": WHEN}
    if cid == "azure.other.change_approval_trace":
        rows = {"activity_log": [activity],
                "activity_log_coverage": [{"id": SCOPE, "retainedFrom": START,
                                           "collectedThrough": END}],
                "change_approval_record": [{"id": SCOPE + "/approvalRecords/1",
                    "resourceId": RESOURCE, "correlationId": "corr", "ticketId": "T-1",
                    "approver": "principal-2", "status": "Approved",
                    "approvedAt": "2026-10-04T00:00:00Z"}]}
        policy = {"windowStart": START, "windowEnd": END}
    else:
        rows = {"activity_log": [activity], "production_change": [{
            "id": SCOPE + "/providers/PEASO/changes/1", "resourceId": RESOURCE,
            "timestamp": WHEN, "correlationId": "corr", "actorId": "principal-1",
            "status": "Succeeded"}]}
        policy = {"window_start": START, "window_end": END,
                  "productionResourceIds": [RESOURCE], "dataPlaneChangesComplete": True}
    return _index(cid, policy, rows)


def test_native_change_approval_window_pass_and_specific_unknown():
    cid = "azure.other.change_approval_trace"
    index = _case(cid)
    # Approval review includes its ending instant; ARM query ends exclusively.
    index["collections"]["activity_log"][0]["queryWindow"]["end"] = "2026-10-10T00:00:01Z"
    assert evaluate_check(cid, {}, index)[0] == "PASS"
    wrong = deepcopy(index)
    wrong["collections"]["activity_log"][0]["queryWindow"]["start"] = "2026-10-02T00:00:00Z"
    status, proof = evaluate_check(cid, {}, wrong)
    assert status == "UNKNOWN"
    assert "query window does not cover" in str(proof)


def test_native_production_change_window_pass_and_specific_unknown():
    cid = "azure_c5_dev_08_02b"
    index = _case(cid)
    assert evaluate_check(cid, {"scope": SCOPE}, index)[0] == "PASS"
    wrong = deepcopy(index)
    wrong["collections"]["activity_log"][0]["queryWindow"]["end"] = "2026-10-09T00:00:00Z"
    status, proof = evaluate_check(cid, {"scope": SCOPE}, wrong)
    assert status == "UNKNOWN"
    assert "query window does not cover" in str(proof)
