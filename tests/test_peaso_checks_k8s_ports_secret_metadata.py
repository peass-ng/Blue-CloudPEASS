"""Secret collection never asks for full objects or reads their data payloads."""
import io
import json
from types import SimpleNamespace
from peaso.collectors.k8s import collect, _metadata_get
from peaso.collectors.azure import AzureReadError
import pytest


class Response:
    def __init__(self, value):
        self.stream = io.BytesIO(json.dumps(value).encode())
        self.bytes_read = 0

    def read(self, amount=None):
        result = self.stream.read() if amount is None else self.stream.read(amount)
        self.bytes_read += len(result)
        return result

    def close(self):
        pass

    def release_conn(self):
        pass


class MetadataAPI:
    server = "https://fixture.invalid"

    def __init__(self, unsupported=False, full=False, mismatch=False):
        self.unsupported, self.full, self.mismatch = unsupported, full, mismatch
        self.calls = []
        self.api_client = SimpleNamespace(call_api=self.call_api, configuration=SimpleNamespace(host=self.server))

    def call_api(self, path, method, **kwargs):
        self.calls.append((path, method, kwargs))
        accept = kwargs["header_params"]["Accept"]
        assert accept in ("application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1",
                          "application/json;as=Table;g=meta.k8s.io;v=v1")
        assert kwargs["_preload_content"] is False and method == "GET"
        if self.unsupported:
            error = RuntimeError("unsupported representation")
            error.status = 406
            raise error
        if self.full:
            self.last_response = Response({"kind": "SecretList", "items": [{"data": {"token": "INERT_VALUE"}}]})
            return self.last_response
        if "PartialObjectMetadataList" in accept:
            return Response({"kind": "PartialObjectMetadataList", "apiVersion": "meta.k8s.io/v1", "metadata": {"resourceVersion": "1"},
                "items": [{"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": {"name": "same",
                    "namespace": namespace, "uid": namespace, "annotations": {"kubernetes.io/service-account.name": "app",
                        "kubernetes.io/service-account.uid": "sa-uid", "api_token": "INERT_EMBEDDED_DATA",
                        "kubectl.kubernetes.io/last-applied-configuration": '{"data":{"token":"INERT_EMBEDDED_DATA"}}'}}}
                    for namespace in ("apps", "other")]})
        params = dict(kwargs["query_params"])
        assert params["includeObject"] == "None"
        assert params["resourceVersion"] == "1"
        secret_type = "Opaque" if "/apps/" in path else "kubernetes.io/service-account-token"
        return Response({"kind": "Table", "apiVersion": "meta.k8s.io/v1", "metadata": {"resourceVersion": "2" if self.mismatch else "1"},
            "columnDefinitions": [{"name": "Name"}, {"name": "Type"}, {"name": "Data"}],
            "rows": [{"cells": ["same", secret_type, 1]}]})


def fixture(api):
    return collect({"provider": "k8s", "auth": {"cluster_id": "fixture"},
        "options": {"inventories": ["secret_metadata"]}}, api=api)


def test_partial_metadata_plus_table_preserves_type_and_serviceaccount_annotation_without_values():
    api = MetadataAPI()
    result = fixture(api)
    row = result["collections"][0]
    assert row["status"] == "collected" and len(row["items"]) == 2
    found = {item["metadata"]["namespace"]: item for item in row["items"]}
    assert found["apps"]["type"] == "Opaque"
    assert found["other"]["type"] == "kubernetes.io/service-account-token"
    assert found["apps"]["metadata"]["annotations"]["kubernetes.io/service-account.name"] == "app"
    assert all("data" not in item and "stringData" not in item for item in row["items"])
    assert len(api.calls) == 3


def test_secret_annotations_are_scrubbed_before_shared_reader_return():
    document = _metadata_get(MetadataAPI(), "/api/v1/secrets", {}, "PartialObjectMetadataList")
    serialized = json.dumps(document)
    assert "INERT_EMBEDDED_DATA" not in serialized and "last-applied-configuration" not in serialized
    assert document["items"][0]["metadata"]["annotations"] == {
        "kubernetes.io/service-account.name": "app", "kubernetes.io/service-account.uid": "sa-uid"}


def test_unsupported_content_negotiation_fails_closed_without_full_json_fallback():
    api = MetadataAPI(unsupported=True)
    result = fixture(api)
    assert result["collections"][0]["status"] == "unknown"
    assert len(api.calls) == 1
    assert result["collections"][0]["error"]["code"] == "406"


def test_wrong_full_secret_representation_is_rejected_before_reading_object_data():
    api = MetadataAPI(full=True)
    with pytest.raises(AzureReadError, match="metadata_representation_unsupported"):
        _metadata_get(api, "/api/v1/secrets", {}, "PartialObjectMetadataList")
    assert api.last_response.bytes_read == 32
    assert api.last_response.stream.read().find(b"INERT_VALUE") >= 0


def test_type_join_cannot_mix_resource_versions_or_namespace_collisions():
    result = fixture(MetadataAPI(mismatch=True))
    assert result["collections"][0]["status"] == "unknown"
    assert result["collections"][0]["error"]["code"] == "metadata_table_version_mismatch"
