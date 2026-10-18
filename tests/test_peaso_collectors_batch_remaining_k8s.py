"""Read-only server-version enrichment and missing/denied boundaries."""
from peaso.collectors.batch_remaining_k8s import attach_server_version


class Reader:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = 0

    def call(self, fn, path):
        self.calls += 1
        if self.error:
            raise self.error
        return fn(path)


class API:
    def __init__(self, response):
        self.response = response

    def get_json(self, path):
        assert path == "/version"
        return self.response


def discovery(status="collected"):
    return {"status": status, "items": [{"provenance": {"cluster_id": "fixture"}}]}


def safe_error(exc):
    return "denied", {"kind": "denied", "code": type(exc).__name__}


def test_collected_version_and_no_duplicate_read():
    page = discovery()
    reader = Reader()
    api = API({"gitVersion": "v1.30.4"})
    attach_server_version(reader, api, page, safe_error)
    attach_server_version(reader, api, page, safe_error)
    assert reader.calls == 1
    assert page["items"][0]["serverVersion"] == {"gitVersion": "v1.30.4"}
    assert page["items"][0]["provenance"]["server_version_source"] == "GET /version"


def test_denied_and_malformed_reads_do_not_create_version():
    for reader, api in ((Reader(error=PermissionError("denied")), API({})),
                        (Reader(), API({"gitVersion": "garbage"}))):
        page = discovery()
        attach_server_version(reader, api, page, safe_error)
        item = page["items"][0]
        assert "serverVersion" not in item
        assert item["_coverage"]["serverVersion"]["status"] == "denied"


def test_incomplete_discovery_causes_no_extra_read():
    page = discovery("partial")
    reader = Reader()
    attach_server_version(reader, API({"gitVersion": "v1.30.4"}), page, safe_error)
    assert reader.calls == 0


def test_real_discovery_version_snapshot_reaches_both_native_scope_checks():
    from types import SimpleNamespace
    from peaso.collectors import k8s
    from peaso.checks import evaluate_check
    from peaso.checks import batch_remaining_k8s  # noqa: F401

    class DiscoveryAPI:
        server = "https://fixture.invalid"
        api_client = SimpleNamespace(configuration=SimpleNamespace(host=server))

        def __init__(self, version):
            self.version = version
            self.calls = []

        def get_json(self, path, params=None):
            self.calls.append(path)
            if path == "/apis":
                return {"groups": []}
            if path == "/version":
                return {"gitVersion": self.version}
            raise AssertionError(path)

    for version, expected in (("v1.30.4", "PASS"), ("v1.28.9", "FAIL")):
        api = DiscoveryAPI(version)
        # The existing PSP discovery path already captures GET /version. The
        # approved main-file hook makes that same read available whenever the
        # two signed api_discovery version checks select this collection.
        snapshot = k8s.collect({"provider": "k8s", "auth": {"cluster_id": "fixture"},
                                "scopes": ["*"], "options": {"inventories": ["api_discovery", "podsecuritypolicy"],
                                "retries": 0, "compliance_policy": {"cluster_id": "fixture",
                                    "max_policy_items": 20, "oldestVersionSupported": "v1.29.0"}}}, api=api)
        envelope = next(row for row in snapshot["collections"] if row["type"] == "api_discovery")
        item = envelope["items"][0]
        assert item["serverVersion"]["gitVersion"] == version
        index = {"context": {"provider": "k8s", "scope": "*", "metadata": snapshot["metadata"]},
                 "collections": {"api_discovery": [envelope]},
                 "api_discovery": [{"type": "api_discovery", "scope": "*", "data": item}]}
        target = {"scope": "*"}
        for check_id in ("k8s_cluster_version_at_least_oldest_supported", "k8s_cluster_version_supported"):
            assert evaluate_check(check_id, target, index)[0] == expected
        assert api.calls.count("/version") == 1
