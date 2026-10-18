"""API Keys repeated-field omission through normal planner, collector and engine."""
import copy
import pytest
from peaso.collectors import gcp
from peaso.engine import collect_snapshot, evaluate_snapshot, plan_collection
from peaso.snapshot import seal

IDS = ("gcp.ports.api_key_meaningful_restrictions", "gcp.ports.iam_api_key_restricts_websites_hosts_apps")
SCOPE = "projects/p-one"
FIELDS = {"serverKeyRestrictions": "allowedIps", "browserKeyRestrictions": "allowedReferrers",
          "androidKeyRestrictions": "allowedApplications", "iosKeyRestrictions": "allowedBundleIds"}
GOOD = {"serverKeyRestrictions": ["192.0.2.1"], "browserKeyRestrictions": ["example.com/*"],
        "androidKeyRestrictions": [{"packageName": "com.example.app", "sha1Fingerprint": "00" * 20}],
        "iosKeyRestrictions": ["com.example.app"]}


class API:
    def __init__(self, response, denied=False):
        self.response, self.denied, self.requests, self.evidence = response, denied, [], []

    def request(self, method, url, **kwargs):
        request_id = f"request-{len(self.requests) + 1}"
        self.requests.append({"method": method, "url": url, **kwargs})
        assert method == "GET"
        assert url == f"https://apikeys.googleapis.com/v2/{SCOPE}/locations/global/keys"
        if self.denied:
            error = gcp.ReadError("denied", "permission_denied")
            error.request_id = request_id
            self.evidence.append({"id": request_id, "url": url, "method": method,
                                  "status": "denied", "error": error.error})
            raise error
        self.evidence.append({"id": request_id, "url": url, "method": method, "status": "collected"})
        return copy.deepcopy(self.response), request_id

    def close(self):
        pass


def observed(monkeypatch, mode, body, *, denied=False, marker=None, page_limit=False, item_marker=None, parent_marker=None):
    restrictions = {mode: body}
    if parent_marker is not None:
        restrictions["_coverage"] = parent_marker
    key = {"name": f"{SCOPE}/locations/global/keys/key-a", "restrictions": restrictions}
    if item_marker is not None:
        key["_coverage"] = item_marker
    response = {"keys": [key]}
    if page_limit:
        response["nextPageToken"] = "another-page"
    api = API(response, denied)
    monkeypatch.setattr(gcp, "Credentials", lambda *a, **kw: None)
    monkeypatch.setattr(gcp, "Transport", lambda *a, **kw: api)
    options = {"include_inherited": False, "concurrency": 1}
    if page_limit:
        options["max_pages"] = 1
    request = {"connector": {"provider": "gcp", "scopes": [SCOPE], "options": options}, "checks": list(IDS)}
    assert plan_collection(request) == ["api_key"]
    snapshot = collect_snapshot(request)
    row = next(c for c in snapshot["collections"] if c["type"] == "api_key")
    assert len(api.requests) == 1
    assert api.requests[0]["params"]["fields"] == "keys(name,uid,displayName,createTime,updateTime,deleteTime,restrictions),nextPageToken"
    assert all("keyString" not in request["params"]["fields"] for request in api.requests)
    if marker and row["items"]:
        row["items"][0]["restrictions"][mode].setdefault("_coverage", {})[FIELDS[mode]] = marker
        snapshot = seal(snapshot)
    findings = [f for f in evaluate_snapshot(snapshot, checks=list(IDS))["findings"] if f["check_id"] in IDS]
    return row, {cid: [f["status"] for f in findings if f["check_id"] == cid] for cid in IDS}


@pytest.mark.parametrize("mode", FIELDS)
def test_nonempty_repeated_caller_list_passes(monkeypatch, mode):
    row, statuses = observed(monkeypatch, mode, {FIELDS[mode]: GOOD[mode]})
    assert row["status"] == "collected"
    assert all(values == ["PASS"] for values in statuses.values())


@pytest.mark.parametrize("mode", FIELDS)
def test_protojson_omitted_empty_list_is_negative(monkeypatch, mode):
    row, statuses = observed(monkeypatch, mode, {})
    body = row["items"][0]["restrictions"][mode]
    assert body[FIELDS[mode]] == []
    assert body["_coverage"][FIELDS[mode]]["status"] == "empty"
    assert all(values == ["FAIL"] for values in statuses.values())


@pytest.mark.parametrize("mode", FIELDS)
def test_explicit_null_and_wrong_type_remain_unknown(monkeypatch, mode):
    for bad in (None, "not-a-list"):
        row, statuses = observed(monkeypatch, mode, {FIELDS[mode]: bad})
        assert row["items"][0]["restrictions"][mode][FIELDS[mode]] == bad
        assert all(values == ["UNKNOWN"] for values in statuses.values())


def test_denied_list_and_field_remain_unresolved(monkeypatch):
    row, statuses = observed(monkeypatch, "androidKeyRestrictions", {}, denied=True)
    assert row["status"] == "denied"
    assert all(values == ["DENIED"] for values in statuses.values())
    for mode in FIELDS:
        _, statuses = observed(monkeypatch, mode, {}, marker={"status": "denied"})
        assert all(values == ["UNKNOWN"] for values in statuses.values())
        _, statuses = observed(monkeypatch, mode, {FIELDS[mode]: []}, marker={"status": "denied"})
        assert all(values == ["UNKNOWN"] for values in statuses.values())


def test_parent_and_item_coverage_block_projection(monkeypatch):
    mode = "browserKeyRestrictions"
    for kwargs in ({"item_marker": {"restrictions": {"status": "denied"}}},
                   {"parent_marker": {mode: {"status": "denied"}}}):
        row, statuses = observed(monkeypatch, mode, {}, **kwargs)
        assert FIELDS[mode] not in row["items"][0]["restrictions"][mode]
        assert all(values == ["UNKNOWN"] for values in statuses.values())


def test_absent_or_malformed_mode_does_not_get_filled(monkeypatch):
    for body in (None, "bad"):
        row, statuses = observed(monkeypatch, "iosKeyRestrictions", body)
        assert row["items"][0]["restrictions"]["iosKeyRestrictions"] == body
        assert all(values == ["UNKNOWN"] for values in statuses.values())


def test_page_limit_keeps_incomplete_inventory(monkeypatch):
    row, statuses = observed(monkeypatch, "androidKeyRestrictions", {}, page_limit=True)
    assert row["status"] == "partial"
    assert row["error"]["code"] == "page_limit"
    assert all("UNKNOWN" in values for values in statuses.values())
