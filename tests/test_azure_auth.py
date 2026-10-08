"""Regression coverage for issue #4: CLI, device-code, and Graph auth gates."""

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


@pytest.fixture
def azure(monkeypatch):
    specification = importlib.util.spec_from_file_location("azure_issue4_tests", "Blue-AzurePEAS.py")
    module = importlib.util.module_from_spec(specification)
    monkeypatch.setitem(sys.modules, specification.name, module)
    specification.loader.exec_module(module)
    for name in ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]:
        monkeypatch.delenv(name, raising=False)
    return module


def auth_args(**values):
    return SimpleNamespace(**{"auth_method": "auto", "tenant_id": None, "client_id": None,
        "client_secret": None, "arm_token": None, "graph_token": None, "no_az_token_cache": False,
        "device_client_id": None, **values})


def test_device_prompt_accepts_the_sdks_three_arguments(azure, monkeypatch, capsys):
    selected = object()
    def device(**kwargs):
        kwargs["prompt_callback"]("https://microsoft.com/devicelogin", "TEST-CODE", datetime(2030, 1, 1, tzinfo=timezone.utc))
        return selected
    monkeypatch.setattr(azure, "DeviceCodeCredential", device)
    assert azure._build_credential(auth_args(auth_method="device-code")) is selected
    assert "TEST-CODE" in capsys.readouterr().out


def test_auto_validates_lazy_cache_before_falling_back_to_device(azure, monkeypatch):
    def no_token(*args, **kwargs):
        raise RuntimeError("No existing Azure login")
    monkeypatch.setattr(azure, "AzureMsalTokenCacheCredential", lambda **kwargs: SimpleNamespace(get_token=no_token))
    selected = object()
    monkeypatch.setattr(azure, "DeviceCodeCredential", lambda **kwargs: selected)
    assert azure._build_credential(auth_args()) is selected
    with pytest.raises(RuntimeError, match="az login"):
        azure._build_credential(auth_args(auth_method="az-cache"))


def test_explicit_device_auth_does_not_select_service_principal_environment(azure, monkeypatch):
    for name in ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]:
        monkeypatch.setenv(name, "environment-value")
    monkeypatch.setattr(azure, "ClientSecretCredential", lambda **kwargs: pytest.fail("Changed selected auth mode"))
    selected = object()
    monkeypatch.setattr(azure, "DeviceCodeCredential", lambda **kwargs: selected)
    assert azure._build_credential(auth_args(auth_method="device-code")) is selected


def test_client_secret_can_combine_explicit_and_environment_fields(azure, monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "selected-tenant")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "selected-secret")
    received = []
    monkeypatch.setattr(azure, "ClientSecretCredential", lambda **kwargs: received.append(kwargs) or "selected")
    assert azure._build_credential(auth_args(auth_method="client-secret", client_id="explicit-app")) == "selected"
    assert received == [{"tenant_id": "selected-tenant", "client_id": "explicit-app", "client_secret": "selected-secret"}]


def test_active_cli_account_and_requested_tenant_are_used_before_raw_cache(azure, monkeypatch):
    seen = []
    selected = SimpleNamespace(get_token=lambda *a, **k: SimpleNamespace(token="selected-token", expires_on=9999999999))
    monkeypatch.setattr(azure.shutil, "which", lambda name: "/usr/bin/az")
    monkeypatch.setattr(azure, "AzureCliCredential", lambda **kwargs: seen.append(kwargs) or selected)
    credential = azure.AzureMsalTokenCacheCredential(tenant_id="selected-tenant")
    monkeypatch.setattr(credential, "_load", lambda: pytest.fail("Used arbitrary raw-cache account"))
    assert credential.get_token("https://management.azure.com/.default").token == "selected-token"
    assert seen == [{"tenant_id": "selected-tenant"}]


def test_custom_azure_configuration_directory_is_respected(azure, monkeypatch, tmp_path):
    monkeypatch.setenv("AZURE_CONFIG_DIR", str(tmp_path))
    assert azure.AzureMsalTokenCacheCredential()._cache_path == str(tmp_path / "msal_token_cache.json")


@pytest.mark.parametrize("arm_only", [False, True])
def test_denied_graph_reads_keep_a_valid_arm_subscription_report(azure, monkeypatch, tmp_path, capsys, arm_only):
    output = tmp_path / "report.json"
    argv = ["Blue-AzurePEAS.py", "--subscription", "subscription", "--hardening", "off", "--no-scan-management-groups", "--out-json", str(output)]
    if arm_only:
        argv += ["--arm-token", "arm-token"]
        monkeypatch.setattr(azure, "_ensure_token_scopes", lambda *a, **k: None)
    monkeypatch.setattr(sys, "argv", argv)
    credential = SimpleNamespace(get_token=lambda *a, **k: SimpleNamespace(token="arm-token"))
    monkeypatch.setattr(azure, "_build_credential", lambda args: credential)
    monkeypatch.setattr(azure, "_jwt_claims", lambda token: {"tid": "tenant", "oid": "auditor"})
    def denied_graph(credential):
        if arm_only:
            pytest.fail("ARM-only audit attempted a Graph request")
        raise RuntimeError("Graph permission check failed (403): missing admin consent")
    monkeypatch.setattr(azure, "_graph_permissions_check", denied_graph)
    monkeypatch.setattr(azure, "SubscriptionClient", lambda credential: SimpleNamespace(subscriptions=SimpleNamespace(list=lambda: [{"subscription_id": "subscription", "display_name": "Fixture"}])))
    def scan(**kwargs):
        assert kwargs["credential"] is credential
        assert kwargs["resolve_principals"] is False
        assert kwargs["scan_entra"] is False
        return azure.SubscriptionScanResult(subscription_id="subscription", subscription_name="Fixture", principals=[], inactive_principals=[], unused_custom_roles=[], external_rbac_principals=[], managed_identity_federated_credentials=[], guest_users=[], group_memberships=[], iam_recommendations=[], errors=[], stats={})
    monkeypatch.setattr(azure, "scan_subscription", scan)
    azure.main()
    report = json.loads(output.read_text())
    assert report["summary"]["successful_subscriptions"] == 1
    assert report["errors"][0]["where"] == "graph_permission_check"
    assert ("ARM-only credentials" if arm_only else "ARM authentication succeeded") in capsys.readouterr().out
