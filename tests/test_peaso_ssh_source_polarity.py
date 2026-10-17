"""Staged inert normal collector/admitted callback tests, not live cloud evidence."""
import copy
from urllib.parse import urlsplit
import pytest
from peaso.checks import evaluate_check
from peaso.collectors import azure

CID = "azure_vm_8_2_1_1_712e1ad"
SCOPE = "/subscriptions/sub"
VM = SCOPE + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"

class Transport:
    tenant = "tenant-a"
    def __init__(self, row):
        self.row = row
        self.paths = []
    def request(self, url, *, body=None, audience=azure.ARM):
        self.paths.append(url)
        path = urlsplit(url).path
        if path == SCOPE + "/providers/Microsoft.Compute/virtualMachines":
            return {"value": [{"id": VM}]}
        if path == VM and "$expand=instanceView" in urlsplit(url).query:
            return copy.deepcopy(self.row)
        if path == VM + "/instanceView":
            return copy.deepcopy(self.row["properties"]["instanceView"])
        return {"value": []}
    def close(self):
        pass

def run(case):
    row = {"id": VM, "type": "Microsoft.Compute/virtualMachines", "properties": {
        "storageProfile": {"osDisk": {"osType": "Linux"}},
        "osProfile": {"linuxConfiguration": {"ssh": {"publicKeys": []}}},
        "instanceView": {"statuses": [{"code": "PowerState/running"}]}}}
    cfg = row["properties"]["osProfile"]["linuxConfiguration"]
    if case in ("key_present", "password_false"):
        cfg["ssh"]["publicKeys"] = [{"path": "/home/test/.ssh/authorized_keys", "keyData": "inert-public-key"}]
    if case == "password_false":
        cfg["disablePasswordAuthentication"] = False
    if case == "missing_keys":
        del cfg["ssh"]["publicKeys"]
    if case == "malformed_keys":
        cfg["ssh"]["publicKeys"] = [{"path": "/home/test/.ssh/authorized_keys", "keyData": ""}]
    if case == "windows":
        row["properties"]["storageProfile"]["osDisk"]["osType"] = "Windows"
        del row["properties"]["osProfile"]
    if case in ("stopped", "deallocated"):
        row["properties"]["instanceView"]["statuses"] = [{"code": "PowerState/" + case}]
        del row["properties"]["osProfile"]
    if case == "ambiguous_power":
        row["properties"]["instanceView"]["statuses"].append({"code": "PowerState/stopped"})
    transport = Transport(row)
    snapshot = azure.collect({"scopes": ["sub"]}, ["vm"], transport=transport)
    envelope = next(e for e in snapshot["collections"] if e["type"] == "vm")
    assert envelope["status"] == "collected"
    item = envelope["items"][0]
    assert item["_provenance"]["representation"] == "full"
    assert any("$expand=instanceView" in url for url in transport.paths)
    if case in ("missing_provenance", "windows", "stopped", "deallocated"):
        del item["_provenance"]
    if case in ("denied", "partial"):
        envelope["status"] = case
    if case == "foreign":
        item["id"] = item["id"].replace("/subscriptions/sub/", "/subscriptions/foreign/")
    index = {"context": {"provider": "azure", "scope": SCOPE},
             "collections": {"vm": [envelope]},
             "vm": [{"type": "vm", "scope": SCOPE, "data": item}]}
    return evaluate_check(CID, item, index)[0]

@pytest.mark.parametrize("case,expected", [
    ("key_present", "FAIL"), ("empty_keys", "PASS"),
    ("password_false", "FAIL"), ("missing_keys", "UNKNOWN"),
    ("malformed_keys", "UNKNOWN"), ("missing_provenance", "UNKNOWN"),
    ("denied", "UNKNOWN"), ("partial", "UNKNOWN"),
    ("foreign", "UNKNOWN"), ("ambiguous_power", "UNKNOWN"),
    ("windows", "NOT_APPLICABLE"), ("stopped", "NOT_APPLICABLE"),
    ("deallocated", "NOT_APPLICABLE"),
])
def test_original_no_bootstrap_key(case, expected):
    assert run(case) == expected
