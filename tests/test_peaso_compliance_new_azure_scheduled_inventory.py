"""Read-only scheduled-query-rule inventory uses the documented paged ARM LIST."""
from urllib.parse import parse_qs, urlsplit

from peaso.collectors import azure
from tests.test_peaso_collectors_azure_perf import FakeAzure, ReadError, rows


PATH = "/subscriptions/sub-a/providers/Microsoft.Insights/scheduledQueryRules"


def test_rule_definitions_are_paged_with_native_fields_and_no_query_execution():
    def handler(url, body, audience):
        assert body is None and audience == azure.ARM
        parsed = urlsplit(url)
        if parsed.path == PATH:
            assert parse_qs(parsed.query)["api-version"] == ["2021-08-01"]
            if parse_qs(parsed.query).get("$skiptoken") == ["next"]:
                return {"value": [{"id": PATH + "/second", "kind": "LogAlert",
                                   "properties": {"enabled": False, "criteria": {"allOf": [{"query": "Heartbeat"}]}}}]}
            return {"value": [{"id": PATH + "/first", "kind": "LogAlert",
                               "properties": {"enabled": True, "scopes": ["/subscriptions/sub-a"],
                                              "criteria": {"allOf": [{"query": "AzureActivity"}]},
                                              "actions": {"actionGroups": ["/subscriptions/sub-a/providers/Microsoft.Insights/actionGroups/a"]}}}],
                    "nextLink": azure.ARM + PATH + "?api-version=2021-08-01&$skiptoken=next"}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["scheduled_query_rule"], transport=api)
    collection = rows(snapshot, "scheduled_query_rule")[0]
    assert collection["status"] == "collected"
    assert len(collection["items"]) == 2
    assert collection["items"][0]["properties"]["criteria"]["allOf"][0]["query"] == "AzureActivity"
    assert [urlsplit(url).path for url, _, _ in api.calls if urlsplit(url).path == PATH] == [PATH, PATH]


def test_denied_rule_list_stays_unavailable_not_empty():
    def handler(url, body, audience):
        if urlsplit(url).path == PATH:
            raise ReadError(403)
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"], "options": {"retries": 0}},
                             ["scheduled_query_rule"], transport=FakeAzure(handler))
    collection = rows(snapshot, "scheduled_query_rule")[0]
    assert collection["status"] not in ("collected", "empty") and collection["items"] == []


def test_rule_list_is_not_silently_skipped_by_subscription_resource_index():
    kinds = ["vnet", "vault", "storage_account", "sql_server", "vm", "nsg", "nic", "disk",
             "public_ip", "scheduled_query_rule"]
    def handler(url, body, audience):
        if body is not None:
            return {"data": []}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a"]}, kinds, transport=api)
    assert rows(snapshot, "scheduled_query_rule")[0]["status"] == "empty"
    assert any(urlsplit(url).path == PATH for url, _, _ in api.calls)
