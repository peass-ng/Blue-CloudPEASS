"""Native scanner bridge and original selected-source authentication regression tests."""
import argparse
import importlib.util
from types import SimpleNamespace
import pytest
from bluepeass import hardening

def load_script(name, filename):
    import sys
    specification = importlib.util.spec_from_file_location(name, filename)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def test_gcloud_refresh_keeps_original_account_and_impersonation(monkeypatch):
    module = load_script("blue_gcp_auth_test", "Blue-GCPPEAS.py")
    calls = []
    monkeypatch.setattr(module, "_get_access_token_from_gcloud", lambda: "initial-token")
    def run_text(command):
        calls.append(command)
        if command[-1] == "account":
            return "selected-account@example.test"
        if command[-1] == "auth/impersonate_service_account":
            return "selected-sa@example.test"
        return "refreshed-token"
    monkeypatch.setattr(module, "run_text", run_text)
    sources = []
    assert module.get_access_token_auto(sa_json=None, token_refresher=sources) == "initial-token"
    assert sources[0]() == "refreshed-token"
    assert calls[-1] == ["gcloud", "auth", "print-access-token", "--account", "selected-account@example.test", "--impersonate-service-account", "selected-sa@example.test"]


def test_successful_gcloud_login_survives_unavailable_refresh_metadata(monkeypatch):
    module = load_script("blue_gcp_refresh_metadata_test", "Blue-GCPPEAS.py")
    monkeypatch.setattr(module, "_get_access_token_from_gcloud", lambda: "selected-token")
    monkeypatch.setattr(module, "run_text", lambda command: (_ for _ in ()).throw(RuntimeError("Config unavailable")))
    sources = []
    assert module.get_access_token_auto(sa_json=None, token_refresher=sources) == "selected-token"
    assert sources[0]() == "selected-token"


def test_service_account_json_source_does_not_fall_back_to_gcloud(monkeypatch):
    module = load_script("blue_gcp_sa_test", "Blue-GCPPEAS.py")
    source = '{"type":"service_account"}'
    monkeypatch.setattr(module, "_get_access_token_from_service_account_json", lambda supplied: "sa-token" if supplied == source else pytest.fail("Changed SA source"))
    monkeypatch.setattr(module, "_get_access_token_from_gcloud", lambda: pytest.fail("Unexpected default identity"))
    sources = []
    assert module.get_access_token_auto(sa_json=source, token_refresher=sources) == "sa-token"
    assert sources[0]() == "sa-token"


def test_adc_refresh_keeps_the_selected_credential_object(monkeypatch):
    module = load_script("blue_gcp_adc_test", "Blue-GCPPEAS.py")
    selected = SimpleNamespace(token="adc-token", refresh=lambda request: None)
    monkeypatch.setattr(module, "_get_access_token_from_gcloud", lambda: None)
    monkeypatch.setattr(module.google.auth, "default", lambda **kwargs: (selected, "project"))
    sources = []
    assert module.get_access_token_auto(sa_json=None, token_refresher=sources) == "adc-token"
    selected.token = "refreshed-adc-token"
    assert sources[0]() == "refreshed-adc-token"



def test_native_disabled_is_offline():
    adapter = SimpleNamespace()
    assert hardening.run_hardening(SimpleNamespace(hardening="off"), adapter, "scope")["status"] == "disabled"


def test_removed_runtime_flags_are_rejected():
    parser = argparse.ArgumentParser()
    hardening.add_hardening_arguments(parser)
    for option in ("--hardening-image", "--hardening-runtime", "--hardening-timeout"):
        with pytest.raises(SystemExit):
            parser.parse_args([option, "obsolete"])


def test_native_bridge_preserves_selected_aws_auth(monkeypatch):
    from peaso import engine
    seen = []
    def scan(request):
        seen.append(request)
        return {"findings": [], "coverage": [], "stats": {"coverage_complete": False}, "snapshot_id": "test"}
    monkeypatch.setattr(engine, "run_scan", scan)
    credentials = SimpleNamespace(access_key="selected", secret_key="selected-secret", token="selected-token")
    session = SimpleNamespace(region_name="eu-west-1", get_credentials=lambda: SimpleNamespace(get_frozen_credentials=lambda: credentials))
    result = hardening.run_hardening(SimpleNamespace(hardening="on"), hardening.AwsCredentials(session), "111111111111")
    assert result["engine"] == "peaso-native"
    assert seen[0]["connector"]["auth"]["aws_access_key_id"] == "selected"
    assert "selected-secret" not in str(result)
