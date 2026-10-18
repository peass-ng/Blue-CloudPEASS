"""Namespace TypeMeta follows the trusted native Kubernetes endpoint."""
from types import SimpleNamespace

import pytest

from peaso.collectors import k8s


class Denied(Exception):
    status = 403


class FakeAPI:
    def __init__(self, response):
        self.response = response
        self.calls = []
        self.api_client = SimpleNamespace(configuration=SimpleNamespace(host="https://fixture.invalid"))

    def get_json(self, path, params=None):
        self.calls.append(path)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def collect(response, scope="*"):
    api = FakeAPI(response)
    snapshot = k8s.collect({"provider": "k8s", "auth": {"cluster_id": "fixture-cluster"},
                            "scopes": [scope], "options": {"inventories": ["namespace"]}}, api=api)
    row = next(collection for collection in snapshot["collections"] if collection["type"] == "namespace")
    return row, api.calls


def namespace(**fields):
    return {"metadata": {"name": "apps", "uid": "namespace-1", "labels": {}}, **fields}


def native_list(item, **fields):
    return {"metadata": {"resourceVersion": "7"}, "items": [item], **fields}


def test_native_list_item_missing_typemeta_uses_namespace_endpoint():
    row, calls = collect(native_list(namespace()))
    assert calls == ["/api/v1/namespaces"]
    assert row["status"] == "collected"
    item = row["items"][0]
    assert item["kind"] == "Namespace"
    assert item["apiVersion"] == "v1"
    assert item["provenance"]["apiVersion"] == "v1"


def test_explicit_matching_typemeta_and_scoped_get():
    row, _ = collect(native_list(namespace(kind="Namespace", apiVersion="v1"),
                                 kind="NamespaceList", apiVersion="v1"))
    assert row["status"] == "collected"
    row, calls = collect(namespace(), scope="apps")
    assert calls == ["/api/v1/namespaces/apps"]
    assert row["status"] == "collected"
    assert (row["items"][0]["kind"], row["items"][0]["apiVersion"]) == ("Namespace", "v1")


@pytest.mark.parametrize("response", [
    native_list(namespace(kind="Pod")),
    native_list(namespace(apiVersion="v2")),
    native_list(namespace(kind=None)),
    native_list(namespace(apiVersion=None)),
    native_list(namespace(), kind="PodList"),
    native_list(namespace(), apiVersion="v2"),
    native_list(namespace(), kind=None),
    native_list(namespace(), apiVersion=None),
])
def test_conflicting_or_null_list_types_cannot_publish_inventory(response):
    row, _ = collect(response)
    assert row["status"] == "malformed"
    assert row["items"] == []


def test_conflicting_scoped_object_cannot_publish_inventory():
    row, _ = collect(namespace(kind="Pod"), scope="apps")
    assert row["status"] == "malformed"
    assert row["items"] == []


def test_denied_and_foreign_scoped_reads_stay_untrusted():
    row, _ = collect(Denied())
    assert row["status"] == "denied"
    assert row["items"] == []
    row, _ = collect({"metadata": {"name": "other", "uid": "namespace-2"}}, scope="apps")
    assert row["status"] == "malformed"
    assert row["items"] == []
