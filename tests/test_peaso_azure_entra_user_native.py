"""Graph roster projection through the public collector, without cloud access."""
from __future__ import annotations

from copy import deepcopy
from urllib.parse import parse_qs, urlsplit

import pytest

from peaso.collectors import azure
from peaso.engine import collect_snapshot, evaluate_snapshot

TENANT = "22222222-2222-2222-2222-222222222222"
OTHER_TENANT = "99999999-9999-9999-9999-999999999999"
SUB = "11111111-1111-1111-1111-111111111111"
SCOPE = "/subscriptions/" + SUB
USER_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
USER_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
CHECKS = ("azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled",
          "azure.other.disabled_identity_24h", "azure.other.human_federated_signin")


class Transport:
    tenant = verified_tenant = TENANT

    def __init__(self, *, pages=None, binding_tenant=TENANT, subscription_status=None):
        self.pages = pages if pages is not None else [[{"id": USER_A, "userPrincipalName": "a@example.test",
            "accountEnabled": True, "userType": "Member", "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}},
            {"id": USER_B, "userPrincipalName": "b@example.test", "accountEnabled": False, "userType": "Guest"}]]
        self.binding_tenant = binding_tenant
        self.subscription_status = subscription_status
        self.calls = []

    def request(self, url, *, body=None, audience=azure.ARM):
        assert body is None
        parsed = urlsplit(url)
        self.calls.append((audience, parsed.path, parse_qs(parsed.query)))
        if audience == azure.ARM and parsed.path == "/subscriptions":
            if self.subscription_status is not None:
                raise self.subscription_status
            return {"value": [{"id": SCOPE, "subscriptionId": SUB, "tenantId": self.binding_tenant}]}
        if audience == azure.GRAPH and parsed.path == "/v1.0/users":
            page = int(parse_qs(parsed.query).get("page", ["1"])[0]) - 1
            data = self.pages[page]
            if isinstance(data, Exception):
                raise data
            response = {"value": deepcopy(data)}
            if page + 1 < len(self.pages):
                response["@odata.nextLink"] = azure.GRAPH + "/v1.0/users?page=" + str(page + 2)
            return response
        raise AssertionError("unexpected metadata read: " + url)


def collect(monkeypatch, api):
    original = azure.collect
    monkeypatch.setattr(azure, "collect", lambda connector, requirements: original(
        connector, requirements, transport=api))
    connector = {"provider": "azure", "scopes": [SUB], "options": {"inventories": ["entra_user"], "retries": 0}}
    return collect_snapshot({"connector": connector, "checks": list(CHECKS)})


def envelope(snapshot, kind):
    return next(c for c in snapshot["collections"] if c["type"] == kind)


def test_fully_paged_roster_is_scoped_but_never_external_proof(monkeypatch):
    api = Transport(pages=[[{"id": USER_A, "accountEnabled": True, "userType": "Member"}],
                           [{"id": USER_B, "accountEnabled": False, "userType": "Guest"}]])
    snapshot = collect(monkeypatch, api)
    parent, roster = envelope(snapshot, "directory_user"), envelope(snapshot, "entra_user")
    assert parent["status"] == roster["status"] == "collected"
    assert parent["scope"] == "/tenants/" + TENANT
    assert roster["scope"] == SCOPE and roster["source_inventory"] == "directory_user"
    assert [row["id"] for row in roster["items"]] == [USER_A, USER_B]
    assert all(row["tenant_id"] == TENANT and row["subscription_id"] == SCOPE for row in roster["items"])
    assert all(row["_provenance"]["source_operation"] == "graph_users_list_read" for row in roster["items"])
    assert all("human" not in row and "effectiveSubscriptionGrants" not in row and
               "cloudAccessRemoval" not in row and "managementSignInDecisions" not in row for row in roster["items"])
    report = evaluate_snapshot(snapshot, checks=list(CHECKS), include_not_applicable=True)
    assert {f["check_id"] for f in report["findings"]} == set(CHECKS)
    assert not any(f["status"] == "PASS" for f in report["findings"])
    assert all(audience in (azure.ARM, azure.GRAPH) and path in ("/subscriptions", "/v1.0/users")
               for audience, path, _ in api.calls)
    assert len([1 for audience, path, _ in api.calls if audience == azure.GRAPH and path == "/v1.0/users"]) == 2


def test_empty_roster_is_exact_empty_and_cannot_prove_mfa(monkeypatch):
    snapshot = collect(monkeypatch, Transport(pages=[[]]))
    roster = envelope(snapshot, "entra_user")
    assert roster["status"] == "empty" and roster["items"] == []
    report = evaluate_snapshot(snapshot, checks=[CHECKS[0]], include_not_applicable=True)
    assert report["findings"][0]["status"] != "PASS"


@pytest.mark.parametrize("mode,expected", [("denied", "denied"), ("partial", "partial"),
                                     ("duplicate", "partial"), ("invalid_id", "partial")])
def test_graph_failure_and_identity_guards_propagate(monkeypatch, mode, expected):
    denied = azure.AzureReadError("fixture_denied", 403)
    if mode == "denied":
        api = Transport(pages=[denied])
    elif mode == "partial":
        api = Transport(pages=[[{"id": USER_A}], denied])
    elif mode == "duplicate":
        api = Transport(pages=[[{"id": USER_A}], [{"id": USER_A}]])
    else:
        api = Transport(pages=[[{"id": USER_A}], [{"id": ""}]])
    snapshot = collect(monkeypatch, api)
    parent, roster = envelope(snapshot, "directory_user"), envelope(snapshot, "entra_user")
    assert parent["status"] == roster["status"] == expected
    assert roster["items"] == [] and roster["source_inventory"] == "directory_user"


@pytest.mark.parametrize("reason,api", [
    ("foreign_binding", Transport(binding_tenant=OTHER_TENANT)),
    ("denied_binding", Transport(subscription_status=azure.AzureReadError("fixture_denied", 403))),
    ("unverified_token", Transport()),
    ("foreign_verified_token", Transport()),
    ("foreign_row", Transport(pages=[[{"id": USER_A, "tenantId": OTHER_TENANT}]])),
])
def test_tenant_and_binding_guards_never_publish_complete_roster(monkeypatch, reason, api):
    if reason == "unverified_token":
        api.verified_tenant = None
    if reason == "foreign_verified_token":
        api.verified_tenant = OTHER_TENANT
    snapshot = collect(monkeypatch, api)
    roster = envelope(snapshot, "entra_user")
    assert roster["status"] not in ("collected", "empty")
    assert roster["items"] == []
