"""Kubernetes full-pagination and metadata-only endpoint regressions."""
from types import SimpleNamespace
import pytest
from peaso.collectors import k8s
from peaso.collectors.azure import _Reader


class API:
    server = "https://fixture.invalid"
    api_client = SimpleNamespace(configuration=SimpleNamespace(host=server))

    def __init__(self, total_pages=11, page_items=1000):
        self.total_pages, self.page_items, self.calls = total_pages, page_items, []

    def get_json(self, path, params=None):
        params = params or {}
        self.calls.append((path, dict(params)))
        page = int(params.get("continue", "0"))
        assert path in ("/api/v1/pods", "/api/v1/replicationcontrollers", "/api/v1/podtemplates")
        return {"metadata": {"resourceVersion": "1", **({"continue": str(page + 1)} if page + 1 < self.total_pages else {})},
            "items": [{"apiVersion": "v1", "metadata": {"name": f"item-{page}-{i}", "namespace": "apps", "uid": f"uid-{page}-{i}"},
                "spec": {"containers": [{"name": "app"}]}} for i in range(self.page_items)]}


def test_k8s_default_has_no_hidden_page_call_or_resource_cap():
    api = API()
    result = k8s.collect({"provider": "k8s", "options": {"inventories": ["pod"]}, "auth": {"cluster_id": "fixture"}}, api=api)
    collection = result["collections"][0]
    assert collection["status"] == "collected" and len(collection["items"]) == 11000
    assert len(api.calls) == 11
    assert result["metadata"]["max_pages"] is None
    assert result["metadata"]["max_resources"] is None and result["metadata"]["max_calls"] is None
    assert result["scopes"] == ["*"]


def test_shared_reader_default_supports_more_than_two_hundred_calls():
    reader = _Reader({})
    for index in range(201):
        assert reader.call(lambda index=index: index) == index
    assert reader.budget.calls == 201


def test_explicit_k8s_page_cap_produces_honest_partial_with_successful_facts():
    api = API(total_pages=3, page_items=1)
    result = k8s.collect({"provider": "k8s", "options": {"inventories": ["pod"], "max_pages": 1},
                          "auth": {"cluster_id": "fixture"}}, api=api)
    assert result["collections"][0]["status"] == "partial"
    assert len(result["collections"][0]["items"]) == 1
    assert len(api.calls) == 1


def test_old_workload_template_endpoints_are_metadata_reads_only():
    api = API(total_pages=1, page_items=1)
    result = k8s.collect({"provider": "k8s", "options": {"inventories": ["podtemplate", "replicationcontroller"]},
                          "auth": {"cluster_id": "fixture"}}, api=api)
    assert {row["type"] for row in result["collections"]} == {"podtemplate", "replicationcontroller"}
    assert {path for path, _ in api.calls} == {"/api/v1/podtemplates", "/api/v1/replicationcontrollers"}
    assert all(row["status"] == "collected" for row in result["collections"])


class DiscoveryAPI(API):
    def __init__(self, openshift=False, denied=False):
        super().__init__()
        self.openshift, self.denied = openshift, denied

    def get_json(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        if path == "/apis":
            return {"groups": [{"name": "security.openshift.io"}]} if self.openshift else {"groups": [{"name": "apps"}]}
        if self.denied:
            from peaso.collectors.azure import AzureReadError
            raise AzureReadError("permission_denied", 403)
        assert path == "/apis/security.openshift.io/v1/securitycontextconstraints"
        return {"metadata": {"resourceVersion": "1"}, "items": [{"apiVersion": "security.openshift.io/v1",
            "metadata": {"name": "restricted"}, "users": ["system:serviceaccount:apps:a"], "groups": ["system:authenticated"],
            "allowHostPID": False, "allowHostIPC": False, "allowHostNetwork": False,
            "allowHostPorts": False, "allowPrivilegedContainer": False}]}


def test_openshift_scc_absence_is_observed_not_applicability_and_never_read():
    api = DiscoveryAPI()
    result = k8s.collect({"provider": "k8s", "options": {"inventories": ["securitycontextconstraint"]},
                          "auth": {"cluster_id": "fixture"}}, api=api)
    row = next(row for row in result["collections"] if row["type"] == "securitycontextconstraint")
    assert row["coverage_status"] == "not_applicable" and row["error"]["code"] == "openshift_api_group_absent"
    assert api.calls == [("/apis", {})]


def test_scc_native_users_groups_flags_and_denied_api_evidence():
    for denied in (False, True):
        api = DiscoveryAPI(openshift=True, denied=denied)
        result = k8s.collect({"provider": "k8s", "options": {"inventories": ["securitycontextconstraint"]},
                              "auth": {"cluster_id": "fixture"}}, api=api)
        row = next(row for row in result["collections"] if row["type"] == "securitycontextconstraint")
        assert row["status"] == ("denied" if denied else "collected")
        if not denied:
            assert row["items"][0]["users"] == ["system:serviceaccount:apps:a"]
            assert row["items"][0]["allowPrivilegedContainer"] is False


def test_only_selected_identity_annotations_are_preserved():
    data = k8s._sanitize({"metadata": {"annotations": {"iam.amazonaws.com/permitted": '["arn:aws:iam::123456789012:role/app"]',
        "openshift.io/scc": "restricted", "api_token": "INERT_MARKER"}}})
    assert data["metadata"]["annotations"]["openshift.io/scc"] == "restricted"
    assert "api_token" not in data["metadata"]["annotations"]
