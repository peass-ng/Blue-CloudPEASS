"""Arc Run Command needs exact child rights and a usable local handler."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az


TID = "azure-arc-machine-runcommands-write"
MACHINE = f"{RG}/providers/Microsoft.HybridCompute/machines/arc"
OTHER = f"{RG}/providers/Microsoft.HybridCompute/machines/other"
COMMAND = MACHINE + "/runCommands/existing"
WRITE = "Microsoft.HybridCompute/machines/runCommands/write"
LINUX = {"publisher": "Microsoft.Cplat.Core", "type": "RunCommandHandlerLinux"}
WINDOWS = {"publisher": "Microsoft.Cplat.Core", "type": "RunCommandHandlerWindows"}
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, grant=MACHINE, existing=False, os_type="Linux", version="1.33.0",
         status="Connected", mode="full", enabled="true", allow=None, block=None,
         service="Running", include_config=True, include_unknown=False):
    config = {"configMode": mode, "extensionsEnabled": enabled,
              "extensionsAllowList": allow, "extensionsBlockList": block}
    props = {"osType": os_type, "status": status, "agentVersion": version,
             "serviceStatuses": {"extensionService": {"status": service}}}
    if include_config:
        props["agentConfiguration"] = config
    machine = {"id": MACHINE, "type": "Microsoft.HybridCompute/machines", "name": "arc",
               "identity": {"principalId": "mi-arc"}, "properties": props}
    other = {"id": OTHER, "type": "Microsoft.HybridCompute/machines", "name": "other",
             "identity": {"principalId": "mi-other"}}
    graph = [machine, other]
    if existing:
        graph.append({"id": COMMAND, "type": "Microsoft.HybridCompute/machines/runCommands",
                      "properties": {}})
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: ([WRITE], [])}, graph=graph)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_parent_create_and_exact_existing_child_reach_machine_identity():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-arc": "conditional"}
    assert reached(_run(grant=COMMAND, existing=True), "u-alice", TID) == {
        "mi-arc": "conditional"}
    assert reached(_run(os_type="Windows", allow=[WINDOWS]), "u-alice", TID) == {
        "mi-arc": "conditional"}


def test_other_machine_and_uninventoried_child_do_not_join():
    assert "mi-arc" not in reached(_run(grant=OTHER), "u-alice", TID)
    assert "mi-arc" not in reached(_run(grant=COMMAND), "u-alice", TID)
    assert "mi-other" not in reached(_run(), "u-alice", TID)


def test_old_agent_and_local_blocks_exclude_run_command():
    for options in ({"version": "1.32.9"}, {"mode": "monitor"},
                    {"enabled": "false"}, {"block": [LINUX]},
                    {"allow": [WINDOWS]}):
        assert reached(_run(**options, include_unknown=True), "u-alice", TID).get("mi-arc") != "conditional"
    assert reached(_run(allow=[LINUX]), "u-alice", TID) == {"mi-arc": "conditional"}


def test_missing_agent_facts_or_disconnection_stay_unresolved():
    for options in ({"version": ""}, {"status": "Disconnected"},
                    {"service": "Stopped"}, {"include_config": False}):
        assert reached(_run(**options, include_unknown=True), "u-alice", TID).get("mi-arc") != "conditional"
