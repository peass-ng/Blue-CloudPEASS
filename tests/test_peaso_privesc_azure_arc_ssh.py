"""Arc administrator SSH must be configured and bound to one machine."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az


TID = "azure-arc-hybrid-connectivity-entra-ssh"
MACHINE = f"{RG}/providers/Microsoft.HybridCompute/machines/arc"
OTHER = f"{RG}/providers/Microsoft.HybridCompute/machines/other"
ENDPOINT = MACHINE + "/providers/Microsoft.HybridConnectivity/endpoints/default"
LIST = "Microsoft.HybridConnectivity/endpoints/listCredentials/action"
EP_WRITE = "Microsoft.HybridConnectivity/endpoints/write"
SSH_WRITE = "Microsoft.HybridConnectivity/endpoints/serviceConfigurations/write"
ADMIN = "Microsoft.HybridCompute/machines/loginAsAdmin/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, relay_scope=ENDPOINT, admin_scope=MACHINE, status="Connected", os_type="Linux",
         endpoint=True, ssh=True, extension=True, extension_state="Succeeded",
         relay_actions=(LIST,), include_unknown=False):
    machine = {"id": MACHINE, "type": "Microsoft.HybridCompute/machines", "name": "arc",
               "identity": {"principalId": "mi-arc"}, "properties": {"status": status,
                                                                "osType": os_type}}
    other = {"id": OTHER, "type": "Microsoft.HybridCompute/machines", "name": "other",
             "identity": {"principalId": "mi-other"}}
    graph = [machine, other]
    if endpoint:
        graph.append({"id": ENDPOINT, "type": "Microsoft.HybridConnectivity/endpoints",
                      "properties": {"type": "default"}})
    if ssh:
        graph.append({"id": ENDPOINT + "/serviceconfigurations/SSH",
                      "type": "Microsoft.HybridConnectivity/endpoints/serviceConfigurations",
                      "properties": {"serviceName": "SSH", "port": 22}})
    if extension:
        graph.append({"id": MACHINE + "/extensions/AADSSHLogin",
                      "type": "Microsoft.HybridCompute/machines/extensions",
                      "properties": {"publisher": "Microsoft.Azure.ActiveDirectory",
                                     "type": "AADSSHLoginForLinux",
                                     "provisioningState": extension_state}})
    snap = az([("u-alice", "User", relay_scope, ROLE_ID),
               ("u-alice", "User", admin_scope, ROLE_ID + "-admin")],
              roles={ROLE_ID: (list(relay_actions), []), ROLE_ID + "-admin": ([], [ADMIN])}, graph=graph)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_exact_arc_endpoint_and_admin_rights_reach_only_its_identity():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-arc": "conditional"}
    assert "mi-other" not in reached(_run(), "u-alice", TID)
    assert reached(_run(relay_scope=MACHINE), "u-alice", TID) == {
        "mi-arc": "conditional"}


def test_wrong_endpoint_or_admin_machine_does_not_join():
    assert "mi-arc" not in reached(_run(relay_scope=OTHER + "/providers/Microsoft.HybridConnectivity/endpoints/default"),
                                    "u-alice", TID)
    assert "mi-arc" not in reached(_run(admin_scope=OTHER), "u-alice", TID)


def test_missing_ssh_setup_or_extension_is_unresolved():
    for options in ({"endpoint": False}, {"ssh": False}, {"extension": False},
                    {"extension_state": "Failed"}, {"status": "Disconnected"},
                    {"os_type": "Windows"}):
        assert reached(_run(**options, include_unknown=True), "u-alice", TID).get("mi-arc") != "conditional"


def test_endpoint_and_ssh_service_can_be_enabled_with_exact_write_rights():
    assert reached(_run(endpoint=False, ssh=False,
                        relay_actions=(LIST, EP_WRITE, SSH_WRITE)), "u-alice", TID) == {
        "mi-arc": "conditional"}
    assert reached(_run(ssh=False, relay_actions=(LIST, SSH_WRITE)), "u-alice", TID) == {
        "mi-arc": "conditional"}
