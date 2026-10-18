"""Public snapshot-ingestion proof for serverless detection; inert retained observations."""
import copy
from pathlib import Path
import runpy

import pytest

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "azure.other.attack_t1648"
HELPERS = runpy.run_path(str(Path(__file__).with_name("test_peaso_compliance_new_sw12.py")))


def imported_snapshot(mode):
    context, index = HELPERS["detection_case"](CID)
    collections = copy.deepcopy([row for rows in index["collections"].values() for row in rows])
    by_kind = {row["type"]: row for row in collections}
    if mode == "disabled_rule":
        by_kind["scheduled_query_rule"]["items"][0]["properties"]["enabled"] = False
    elif mode == "missing_test":
        by_kind["azure_detection_test"].update(status="empty", items=[])
    elif mode == "denied_test":
        by_kind["azure_detection_test"].update(status="denied", items=[])
    elif mode == "foreign_test":
        by_kind["azure_detection_test"]["items"][0]["source_id"] = HELPERS["FUNCTION"].replace(HELPERS["SCOPE"], HELPERS["OTHER"])
    return make_snapshot("azure", [context["scope"]], collections,
                         created_at=context["created_at"], metadata=context["metadata"])


@pytest.mark.parametrize("mode,expected", [
    ("complete", "PASS"), ("disabled_rule", "FAIL"),
    ("missing_test", "UNKNOWN"), ("denied_test", "DENIED"),
    ("foreign_test", "UNKNOWN"),
])
def test_serverless_detection_public_snapshot_ingress(mode, expected, monkeypatch):
    snapshot = imported_snapshot(mode)
    before = copy.deepcopy(snapshot)
    def no_live_collection(*args, **kwargs):
        raise AssertionError("retained-evidence ingestion must not contact cloud")
    monkeypatch.setattr("peaso.collectors.collect_live", no_live_collection)
    request = {"connector": {"provider": "azure", "scopes": snapshot["scopes"],
                             "options": {"snapshot": snapshot}}, "checks": [CID]}
    imported = collect_snapshot(request)
    report = evaluate_snapshot(imported, checks=[CID])
    rows = [row for row in report["findings"] if row["check_id"] == CID]
    assert len(rows) == 1
    assert rows[0]["status"] == expected
    assert snapshot == before
    assert imported == snapshot
