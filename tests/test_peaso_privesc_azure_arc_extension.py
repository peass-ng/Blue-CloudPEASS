"""Arc Custom Script rights must match the machine and local agent policy."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az


TID = "azure-arc-machine-extensions-write"
MACHINE = f"{RG}/providers/Microsoft.HybridCompute/machines/arc"
OTHER = f"{RG}/providers/Microsoft.HybridCompute/machines/other"
EXTENSION = MACHINE + "/extensions/script"
WRITE = "Microsoft.HybridCompute/machines/extensions/write"
WIN = {"publisher": "Microsoft.Compute", "type": "CustomScriptExtension"}
LINUX = {"publisher": "Microsoft.Azure.Extensions", "type": "CustomScript"}
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, grant=MACHINE, os_type="Linux", status="Connected", mode="full",
         enabled="true", allow=None, block=None, service="Running",
         existing=LINUX, include_config=True, include_unknown=False):
    config = {"configMode": mode, "extensionsEnabled": enabled,
              "extensionsAllowList": allow, "extensionsBlockList": block}
    props = {"osType": os_type, "status": status,
             "serviceStatuses": {"extensionService": {"status": service}}}
    if include_config:
        props["agentConfiguration"] = config
    machine = {"id": MACHINE, "type": "Microsoft.HybridCompute/machines", "name": "arc",
               "identity": {"principalId": "mi-arc"}, "properties": props}
    other = {"id": OTHER, "type": "Microsoft.HybridCompute/machines", "name": "other",
             "identity": {"principalId": "mi-other"}, "properties": {"osType": "Linux", "status": "Connected"}}
    graph = [machine, other]
    if existing:
        graph.append({"id": EXTENSION, "type": "Microsoft.HybridCompute/machines/extensions",
                      "properties": existing})
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: ([WRITE], [])}, graph=graph)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_parent_create_and_exact_existing_custom_script_child_reach_machine():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-arc": "conditional"}
    assert reached(_run(grant=EXTENSION), "u-alice", TID) == {"mi-arc": "conditional"}
    assert reached(_run(os_type="Windows", existing=WIN), "u-alice", TID) == {
        "mi-arc": "conditional"}


def test_other_machine_and_unrelated_existing_extension_do_not_join():
    assert "mi-arc" not in reached(_run(grant=OTHER), "u-alice", TID)
    assert "mi-arc" not in reached(_run(grant=EXTENSION,
                                        existing={"publisher": "Microsoft.Azure.Monitor",
                                                  "type": "AzureMonitorLinuxAgent"}), "u-alice", TID)
    assert "mi-arc" not in reached(_run(grant=EXTENSION, existing=None), "u-alice", TID)


def test_agent_controls_block_custom_script():
    for options in ({"mode": "monitor"}, {"enabled": "false"},
                    {"allow": [{"publisher": "Microsoft.Azure.Monitor",
                                "type": "AzureMonitorLinuxAgent"}]},
                    {"block": [LINUX]}):
        assert reached(_run(**options, include_unknown=True), "u-alice", TID).get("mi-arc") != "conditional"
    assert reached(_run(allow=[LINUX]), "u-alice", TID) == {"mi-arc": "conditional"}


def test_disconnected_agent_and_missing_configuration_are_unresolved():
    for options in ({"status": "Disconnected"}, {"service": "Stopped"},
                    {"include_config": False}):
        assert reached(_run(**options, include_unknown=True), "u-alice", TID).get("mi-arc") != "conditional"
