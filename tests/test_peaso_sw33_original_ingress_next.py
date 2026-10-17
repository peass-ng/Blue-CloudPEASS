"""Original SW33 public evaluator ingress regressions."""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from tests.test_peaso_azure_database_alert_delivery_binding import observed, proof_of
from tests.test_peaso_azure_wave_change_native_integration import _case

BACKUP = "azure.other.database_backup_alert"
CHANGE = "azure.other.change_approval_trace"


def status(cid, index):
    return evaluate_check(cid, {}, index)[0]


def test_backup_independent_delivery_and_equivalent_timezone_instants():
    index = observed()
    proof = proof_of(index)
    signal = proof["signals"]["disabled"]
    signal["triggerObservation"]["eventAt"] = "2026-10-05T02:00:00+02:00"
    signal["deliveryObservation"]["windowStart"] = "2026-10-05T02:00:00+02:00"
    signal["deliveryObservation"]["windowEnd"] = "2026-10-05T02:10:00+02:00"
    signal["deliveryObservation"]["deliveries"][0]["deliveredAt"] = "2026-10-05T02:05:00+02:00"
    assert status(BACKUP, index) == "PASS"
    signal["deliveryObservation"]["deliveries"] = []
    assert status(BACKUP, index) == "FAIL"


@pytest.mark.parametrize("field", ["ticketId", "approver"])
def test_change_blank_approval_authority_is_unresolved(field):
    index = _case(CHANGE)
    index["collections"]["activity_log"][0]["queryWindow"]["end"] = "2026-10-10T00:00:01Z"
    index["collections"]["change_approval_record"][0]["items"][0][field] = "   "
    assert status(CHANGE, index) == "UNKNOWN"


def test_change_empty_correlation_cannot_be_approval_join():
    index = _case(CHANGE)
    index["collections"]["activity_log"][0]["queryWindow"]["end"] = "2026-10-10T00:00:01Z"
    index["collections"]["activity_log"][0]["items"][0]["correlationId"] = ""
    index["collections"]["change_approval_record"][0]["items"][0]["correlationId"] = ""
    assert status(CHANGE, index) == "UNKNOWN"


def test_change_equivalent_timezone_instants_reach_pass_and_late_failure():
    index = _case(CHANGE)
    index["collections"]["activity_log"][0]["queryWindow"]["end"] = "2026-10-10T02:00:01+02:00"
    approval = index["collections"]["change_approval_record"][0]["items"][0]
    approval["approvedAt"] = "2026-10-04T02:00:00+02:00"
    assert status(CHANGE, index) == "PASS"
    approval["approvedAt"] = "2026-10-05T02:00:01+02:00"
    assert status(CHANGE, index) == "FAIL"


def test_missing_change_approval_failure_survives_other_blank_ticket():
    from tests.test_peaso_azure_change_approval_aggregate_failure import facts, event, approval
    index = facts([event("missing"), event("blank")], [approval("blank", status="Approved")])
    index["collections"]["change_approval_record"][0]["items"][0]["ticketId"] = "  "
    outcome, evidence = evaluate_check(CHANGE, {}, index)
    assert outcome == "FAIL", evidence
    assert event("missing")["id"] in evidence["changes_without_predating_approval"]
    assert event("blank")["id"] in evidence["unresolved_changes"]
