"""A collected marker cannot attest an optional field absent from its payload."""
import pytest
from peaso.checks import evaluate_check

FULL = {"representation": "full"}

@pytest.mark.parametrize("cid,path,base", [
    ("gcp.reviewed.network.flow_logs", "purpose", {"enableFlowLogs": True}),
    ("gcp.reviewed.storage.versioning", "versioning.enabled", {"versioning": {}}),
    ("gcp.reviewed.storage.access_logging", "logging", {}),
])
def test_registered_missing_collected_fact_is_not_documented_omission(cid, path, base):
    item = {**base, "_provenance": FULL}
    parent = item
    parts = path.split(".")
    for part in parts[:-1]: parent = parent[part]
    parent["_coverage"] = {parts[-1]: {"status": "collected"}}
    assert evaluate_check(cid, item)[0] == "UNKNOWN"

@pytest.mark.parametrize("cid,item,wanted", [
    ("gcp.reviewed.network.flow_logs", {"enableFlowLogs": True}, "PASS"),
    ("gcp.reviewed.storage.versioning", {"versioning": {}}, "FAIL"),
    ("gcp.reviewed.storage.access_logging", {}, "FAIL"),
])
@pytest.mark.parametrize("explicit_empty", [False, True])
def test_registered_confirmed_native_omission_keeps_default(cid, item, wanted, explicit_empty):
    item = {**item, "_provenance": FULL}
    if explicit_empty:
        if "flow_logs" in cid: item["_coverage"] = {"purpose": {"status": "empty"}}
        elif "versioning" in cid: item["versioning"] = {"_coverage": {"enabled": {"status": "empty"}}}
        else: item["_coverage"] = {"logging": {"status": "empty"}}
    assert evaluate_check(cid, item)[0] == wanted
