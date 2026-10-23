"""Analysis Services administrator writes must apply to an inventoried server."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


SERVER = f"{RG}/providers/Microsoft.AnalysisServices/servers/main"
OTHER = f"{RG}/providers/Microsoft.AnalysisServices/servers/other"
ACTION = "Microsoft.AnalysisServices/servers/write"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-analysisservices-server-admin-write")


def _run(*, scope=SERVER, actions=(ACTION,), servers=(SERVER,), denied=False):
    rows = [{"id": rid, "type": "Microsoft.AnalysisServices/servers",
             "name": rid.rsplit("/", 1)[-1], "properties": {"state": "Succeeded"}}
            for rid in servers]
    extra = [("analysis_server", SUB, rows, "collected" if rows else "empty")]
    if denied:
        extra.append(("deny_assignment", SUB, [{
            "id": SERVER + "/providers/Microsoft.Authorization/denyAssignments/one",
            "properties": {"scope": SERVER, "principals": [{"id": "u-alice"}],
                           "permissions": [{"actions": [ACTION]}]}}], "collected"))
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              extra=extra)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    return {key: confidence for key, confidence in reached(result, "u-alice", ENTRY["id"]).items()
            if key.startswith("azure_dataplane_admin:")}


def test_native_server_and_exact_grant_reach_conditional_admin():
    assert list(_run().values()) == ["conditional"]


def test_other_server_or_missing_action_does_not_reach_target():
    assert not _run(scope=OTHER)
    assert not _run(actions=())


def test_no_server_does_not_name_a_dataplane_admin():
    assert not _run(servers=())


def test_deny_assignment_blocks_exact_server_write():
    assert not _run(denied=True)
