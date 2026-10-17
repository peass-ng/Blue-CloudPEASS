"""Public collector and engine proof for existing native SAS policy failure path."""
from copy import deepcopy
import json
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot, plan_collection

SUB = "11111111-1111-1111-1111-111111111111"
SCOPE = "/subscriptions/" + SUB
ACCOUNT = SCOPE + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account"
CID = "azure.cis.shared_access_signature_tokens_expire_within_hour"


class Transport:
    tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"

    def __init__(self, mode):
        self.mode = mode
        self.calls = []

    def request(self, url, *, body=None, audience=azure.ARM):
        assert body is None and audience == azure.ARM
        self.calls.append(url)
        path = urlsplit(url).path
        if path == SCOPE + "/providers/Microsoft.Storage/storageAccounts":
            return {"value": [{"id": ACCOUNT, "name": "account", "type": "Microsoft.Storage/storageAccounts",
                               "properties": {}}]}
        if path == ACCOUNT:
            if self.mode == "denied":
                raise azure.AzureReadError("fixture_denied", 403)
            props = {"otherField": "preserved-value", "privateKey": "DO_NOT_PERSIST"}
            if self.mode == "log":
                props["sasPolicy"] = {"sasExpirationPeriod": "00.01:00:00", "expirationAction": "Log"}
            elif self.mode == "block":
                props["sasPolicy"] = {"sasExpirationPeriod": "00.01:00:00", "expirationAction": "Block"}
            return {"id": ACCOUNT, "name": "account", "type": "Microsoft.Storage/storageAccounts",
                    "properties": props}
        return {"value": []}


@pytest.mark.parametrize("mode,expected,reason", [
    ("denied", "UNKNOWN", "dependency incomplete"),
    ("absent", "FAIL", "absent enforcing SAS policy"),
    ("log", "FAIL", "does not enforce one-hour SAS limit"),
    ("block", "UNKNOWN", "storage_sas_issuance"),
])
def test_public_engine_native_storage_get(mode, expected, reason, monkeypatch):
    api = Transport(mode)
    original = azure.collect
    monkeypatch.setattr(azure, "collect", lambda connector, requirements: original(
        connector, requirements, transport=api))
    connector = {"provider": "azure", "scopes": [SUB], "options": {"retries": 0}}
    snapshot = collect_live(connector, plan_collection({"connector": connector, "checks": [CID]}))
    report = evaluate_snapshot(snapshot, checks=[CID], include_not_applicable=True)
    account = next(c for c in snapshot["collections"] if c["type"] == "storage_account")
    finding = next(f for f in report["findings"] if f.get("native_resource_id", "").casefold() == ACCOUNT.casefold())
    assert finding["status"] == expected, finding
    if reason:
        assert reason in finding["evidence"].get("reason", ""), finding
    assert any(urlsplit(url).path == ACCOUNT for url in api.calls)
    assert all("listKeys" not in url and "/keys/" not in url for url in api.calls)
    assert "DO_NOT_PERSIST" not in json.dumps(snapshot)
    if mode != "denied":
        row = account["items"][0]
        assert row["properties"]["otherField"] == "preserved-value"
        assert row["_provenance"]["representation"] == "full"
        assert row["_provenance"]["source_operation"] == "get"
    else:
        assert account["status"] not in ("collected", "empty")
        assert account["error"]["code"] == "403"
