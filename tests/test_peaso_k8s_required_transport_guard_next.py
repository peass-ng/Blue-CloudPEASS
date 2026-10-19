"""Required Kubernetes SDK transport guard; all clients are local and inert."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from peaso.collectors import k8s


@pytest.mark.parametrize("rest_client", [None, SimpleNamespace(), SimpleNamespace(pool_manager=None)])
def test_wrap_rejects_client_without_required_pool(rest_client):
    closed = []
    client = SimpleNamespace(configuration=SimpleNamespace(host="https://cluster.example"),
                             rest_client=rest_client, close=lambda: closed.append(True))
    with pytest.raises(ValueError, match="pool_manager"):
        k8s._wrap_client(client)
    assert not closed  # Direct caller retains ownership of its client.


def test_new_direct_api_closes_client_and_inline_material_on_missing_pool(monkeypatch):
    from kubernetes import client

    created = []
    def create(configuration):
        obj = SimpleNamespace(configuration=configuration, rest_client=SimpleNamespace(),
                              close=lambda: setattr(obj, "closed", True), closed=False)
        created.append(obj)
        return obj
    monkeypatch.setattr(client, "ApiClient", create)
    with pytest.raises(ValueError, match="pool_manager"):
        k8s._new_api({"method": "token", "server": "https://cluster.example", "token": "test-token",
                      "ca_cert_data": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"})
    assert len(created) == 1 and created[0].closed
    assert not Path(created[0].configuration.ssl_ca_cert).exists()


@pytest.mark.parametrize("method", ["in_cluster", "kubeconfig"])
def test_new_loaded_api_closes_client_on_missing_pool(monkeypatch, method, tmp_path):
    from kubernetes import client, config

    obj = SimpleNamespace(rest_client=SimpleNamespace(pool_manager=None), closed=False)
    obj.close = lambda: setattr(obj, "closed", True)
    if method == "in_cluster":
        monkeypatch.setattr(config, "load_incluster_config", lambda **kwargs: None)
        monkeypatch.setattr(client, "ApiClient", lambda configuration: obj)
        auth = {"method": method}
    else:
        import json
        path = tmp_path / 'config'
        path.write_text(json.dumps({'current-context': 'scan',
            'clusters': [{'name': 'cluster', 'cluster': {'server': 'https://cluster.example'}}],
            'users': [{'name': 'reader', 'user': {'token': 'customer-token'}}],
            'contexts': [{'name': 'scan', 'context': {'cluster': 'cluster', 'user': 'reader'}}]}))
        monkeypatch.setattr(client, "ApiClient", lambda configuration: obj)
        auth = {"method": method, "kubeconfig": str(path)}
    with pytest.raises(ValueError, match="pool_manager"):
        k8s._new_api(auth)
    assert obj.closed


def test_supported_sdk_client_is_wrapped_without_io():
    from kubernetes import client

    configuration = client.Configuration()
    configuration.host = "https://cluster.example"
    sdk = client.ApiClient(configuration)
    try:
        original = sdk.rest_client.pool_manager
        assert original is not None
        api = k8s._wrap_client(sdk)
        assert api.api_client is sdk
        assert isinstance(sdk.rest_client.pool_manager, k8s._BoundedPool)
        assert sdk.rest_client.pool_manager.pool is original
    finally:
        sdk.close()


def test_mock_pool_still_wraps_and_rejects_write_before_io():
    calls = []
    pool = SimpleNamespace(request=lambda *args, **kwargs: calls.append((args, kwargs)))
    sdk = SimpleNamespace(configuration=SimpleNamespace(host="https://cluster.example"),
                          rest_client=SimpleNamespace(pool_manager=pool))
    api = k8s._wrap_client(sdk)
    assert api.api_client is sdk
    with pytest.raises(ValueError, match="read-only"):
        sdk.rest_client.pool_manager.request("POST", "https://cluster.example/api/v1/pods")
    assert calls == []
