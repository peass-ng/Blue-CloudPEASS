"""Authentication boundaries and report completeness are security contracts."""

import argparse
import base64
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluepeass import hardening


def options(**values):
    parser = argparse.ArgumentParser()
    hardening.add_hardening_arguments(parser)
    args = parser.parse_args([])
    for key, value in values.items():
        setattr(args, key, value)
    return args


def export(*rows, error=""):
    return {"runs": [{"mod": "aws-compliance", "version": "fixture", "document": {
        "group_id": "root_result_group", "groups": [{"controls": [{
            "control_id": "control.fixture", "title": "Fixture", "severity": "high",
            "results": list(rows), "run_error": error,
        }]}]}}]}


def test_all_statuses_nested_errors_and_metadata_survive():
    rows = [{"resource": status, "status": status, "reason": "evidence", "dimensions": [{"key": "region", "value": "test"}]} for status in ["alarm", "ok", "info", "skip", "error"]]
    result = hardening.normalize_results(export(*rows, error="Denied read"), "aws", "account")
    assert result["summary"]["by_status"] == {"FAIL": 1, "PASS": 1, "MANUAL": 1, "SKIP": 1, "ERROR": 1}
    assert result["status"] == "partial"
    assert len(result["errors"]) == 2
    assert result["findings"][0]["severity"] == "high"
    assert result["findings"][0]["control_id"] == "aws_compliance.control.fixture"
    assert result["findings"][0]["dimensions"]["region"] == "test"


def test_dedup_keeps_distinct_dimensions_and_failed_checks_without_rows():
    first = {"resource": "resource", "status": "alarm", "reason": "evidence", "dimensions": [{"key": "id", "value": "1"}]}
    second = {**first, "dimensions": [{"key": "id", "value": "2"}]}
    assert len(hardening.normalize_results(export(first, first, second), "aws", "account")["findings"]) == 2
    result = hardening.normalize_results(export(error="HTTP 403"), "aws", "account")
    assert result["errors"][0]["error"] == "HTTP 403"
    assert not result["coverage"]["complete"]


def test_zero_resources_is_visible_and_missing_report_is_not_success():
    result = hardening.normalize_results(export(), "aws", "account")
    assert result["coverage"]["zero_result_controls"] == ["aws_compliance.control.fixture"]
    assert hardening.normalize_results({"runs": []}, "aws", "account")["status"] == "partial"


def test_native_json_null_dimensions_do_not_drop_findings():
    row = {"resource": "resource", "status": "alarm", "reason": "evidence", "dimensions": None}
    result = hardening.normalize_results(export(row), "aws", "account")
    assert result["findings"][0]["dimensions"] == {}
    assert result["summary"]["by_status"] == {"FAIL": 1}


def test_automatic_denied_reads_and_disabled_mode_never_launch_docker(monkeypatch):
    adapter = SimpleNamespace(probe=lambda: [{"read": "read", "allowed": False}])
    monkeypatch.setattr(hardening.subprocess, "run", lambda *a, **k: pytest.fail("Unexpected process"))
    assert hardening.run_hardening(options(), adapter, "target")["status"] == "skipped"
    adapter.probe = lambda: pytest.fail("Disabled mode made an API call")
    assert hardening.run_hardening(options(hardening="off"), adapter, "target")["status"] == "disabled"


def test_aws_uses_resolved_session_credentials_not_host_default(tmp_path):
    resolved = SimpleNamespace(access_key="selected-key", secret_key="selected-secret", token="selected-token")
    session = SimpleNamespace(region_name="eu-west-1", get_credentials=lambda: SimpleNamespace(get_frozen_credentials=lambda: resolved))
    hardening.AwsCredentials(session).write(tmp_path)
    document = json.loads((tmp_path / "aws-credentials.json").read_text())
    assert document["SessionToken"] == "selected-token"
    assert document["AccessKeyId"] == "selected-key"
    assert 'regions = ["*"]' in (tmp_path / "aws.spc").read_text()
    assert 'plugin = "aws@1.34.0"' in (tmp_path / "aws.spc").read_text()


def test_connection_versions_match_the_preinstalled_image():
    dockerfile = Path("Dockerfile.hardening").read_text()
    for plugin, version in hardening.PLUGIN_VERSIONS.items():
        assert plugin + "@" + version in dockerfile


def test_gcp_keeps_token_scope_quota_and_escapes_hcl(tmp_path):
    hardening.GcpCredentials('token${danger}', "selected-project", "quota-project").write(tmp_path)
    config = (tmp_path / "gcp.spc").read_text()
    assert 'project = "selected-project"' in config
    assert 'quota_project = "quota-project"' in config
    assert 'token$${danger}' in config


def test_gcp_refreshes_from_selected_source_before_starting(tmp_path):
    adapter = hardening.GcpCredentials("expired-token", "selected-project", token_supplier=lambda: "refreshed-selected-token")
    adapter.write(tmp_path)
    config = (tmp_path / "gcp.spc").read_text()
    assert "refreshed-selected-token" in config
    assert "expired-token" not in config


def test_gcp_preflight_uses_a_fresh_token_after_a_long_iam_audit(monkeypatch):
    def http(url, token, **kwargs):
        assert token == "fresh-token"
        return {"permissions": ["compute.instances.list"]}
    monkeypatch.setattr(hardening, "_http", http)
    adapter = hardening.GcpCredentials("expired-token", "project", token_supplier=lambda: "fresh-token")
    assert any(item["allowed"] for item in adapter.probe())


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


@pytest.mark.parametrize("mode", ["client-secret", "device-code", "az-cache", "direct-token"])
def test_azure_authentication_modes_supply_the_selected_credential(monkeypatch, tmp_path, mode):
    module = load_script("blue_azure_auth_" + mode.replace("-", "_"), "Blue-AzurePEAS.py")
    selected = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="selected-token", expires_on=9999999999))
    for name in ["ClientSecretCredential", "DeviceCodeCredential", "AzureMsalTokenCacheCredential"]:
        monkeypatch.setattr(module, name, lambda **kwargs: selected)
    args = SimpleNamespace(auth_method=mode if mode != "direct-token" else "auto", arm_token="selected-arm" if mode == "direct-token" else None, graph_token="selected-graph",
        client_id="client" if mode == "client-secret" else None, client_secret="secret" if mode == "client-secret" else None,
        tenant_id="tenant", no_az_token_cache=mode == "device-code", device_client_id=None)
    credential = module._build_credential(args)
    if mode != "direct-token":
        assert credential is selected
    hardening.AzureCredentials(credential, "subscription", "tenant").write(tmp_path)
    tokens = json.loads((tmp_path / "azure-tokens.json").read_text())["tokens"]
    assert tokens["https://management.azure.com"]["token"] == ("selected-arm" if mode == "direct-token" else "selected-token")
    assert tokens["https://graph.microsoft.com"]["token"] == ("selected-graph" if mode == "direct-token" else "selected-token")


def test_azure_cache_can_use_existing_cli_login_when_silent_acquisition_fails(monkeypatch):
    module = load_script("azure_cache_fallback_test", "Blue-AzurePEAS.py")
    selected = SimpleNamespace(get_token=lambda *a, **k: SimpleNamespace(token="selected-token", expires_on=9999999999))
    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/az")
    monkeypatch.setattr(module, "AzureCliCredential", lambda: selected)
    credential = module.AzureMsalTokenCacheCredential()
    monkeypatch.setattr(credential, "_load", lambda: None)
    credential._app = SimpleNamespace(get_accounts=lambda: [{}], acquire_token_silent=lambda *a, **k: None)
    assert credential.get_token("https://management.azure.com/.default").token == "selected-token"
    assert credential._cli is selected


def test_azure_cache_rejects_a_different_cli_principal_for_graph(monkeypatch):
    module = load_script("azure_cache_identity_test", "Blue-AzurePEAS.py")
    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/az")
    monkeypatch.setattr(module, "_jwt_claims", lambda token: {"tid": "tenant", "oid": token})
    monkeypatch.setattr(module, "AzureCliCredential", lambda: SimpleNamespace(get_token=lambda *a, **k: SimpleNamespace(token="different-principal")))
    credential = module.AzureMsalTokenCacheCredential()
    monkeypatch.setattr(credential, "_load", lambda: None)
    credential._app = SimpleNamespace(get_accounts=lambda: [{}], acquire_token_silent=lambda scopes, **kwargs: {"access_token": "selected-principal", "expires_on": 9999999999} if "management" in scopes[0] else None)
    credential.get_token("https://management.azure.com/.default")
    with pytest.raises(RuntimeError, match="refusing to switch identities"):
        credential.get_token("https://graph.microsoft.com/.default")
    assert credential._cli is None


def test_azure_arm_only_still_creates_graph_connection_with_explicit_tenant(tmp_path):
    def get_token(scope):
        if "graph" in scope:
            raise ValueError("Graph unavailable")
        return SimpleNamespace(token="selected-arm-token", expires_on=9999999999)
    hardening.AzureCredentials(SimpleNamespace(get_token=get_token), "subscription", "tenant").write(tmp_path)
    document = json.loads((tmp_path / "azure-tokens.json").read_text())
    assert document["tenant"] == "tenant"
    assert "https://graph.microsoft.com" not in document["tokens"]
    assert document["tokens"]["https://management.core.windows.net"]["token"] == "selected-arm-token"
    assert 'tenant_id' not in (tmp_path / "azure.spc").read_text()


@pytest.mark.parametrize("auth_kind", ["token", "certificate", "basic"])
def test_kubeconfig_materializes_selected_auth_and_local_tls(tmp_path, auth_kind):
    certificate = tmp_path / "client.crt"
    certificate.write_text("certificate")
    config = SimpleNamespace(host="https://127.0.0.1:8443", verify_ssl=True, tls_server_name=None, ssl_ca_cert=str(certificate), proxy=None,
        cert_file=str(certificate) if auth_kind == "certificate" else None, key_file=str(certificate) if auth_kind == "certificate" else None,
        username="user" if auth_kind == "basic" else None, password="password", get_api_key_with_prefix=lambda name: "Bearer selected-token" if auth_kind == "token" else None)
    hardening.KubernetesCredentials(SimpleNamespace(api_client=SimpleNamespace(configuration=config))).write(tmp_path)
    document = json.loads((tmp_path / "kubeconfig").read_text())
    cluster = document["clusters"][0]["cluster"]
    assert cluster["server"] == "https://host.docker.internal:8443"
    assert cluster["tls-server-name"] == "127.0.0.1"
    assert base64.b64decode(cluster["certificate-authority-data"]) == b"certificate"
    user = document["users"][0]["user"]
    assert "exec" not in user
    assert (user.get("token") == "selected-token") if auth_kind == "token" else bool(user)


def test_docker_receives_no_credential_values_and_temp_files_are_removed(tmp_path, monkeypatch):
    seen = []
    adapter = SimpleNamespace(provider="aws", probe=lambda: [{"allowed": True}], write=lambda root: hardening._write_private(root / "credentials.json", {"secret": "do-not-expose"}))
    monkeypatch.setattr(hardening.shutil, "which", lambda cmd: "/usr/bin/docker")
    def execute(command, **kwargs):
        seen.append(command)
        if command[1] == "run":
            mounts = [command[i + 1] for i, item in enumerate(command) if item == "--mount"]
            output = Path(next(m.split("src=")[1].split(",")[0] for m in mounts if "dst=/output" in m))
            (output / "result.json").write_text(json.dumps(export({"resource": "resource", "status": "alarm", "reason": "evidence"})))
        return SimpleNamespace(returncode=0, stderr="")
    monkeypatch.setattr(hardening.subprocess, "run", execute)
    result = hardening.run_hardening(options(hardening_out_dir=str(tmp_path)), adapter, "target/../../untrusted")
    assert result["summary"]["by_status"]["FAIL"] == 1
    assert "do-not-expose" not in str(seen)
    auth_mount = next(x for x in seen[0] if "dst=/input" in x)
    assert not Path(auth_mount.split("src=")[1].split(",")[0]).exists()
    assert Path(result["exports_directory"]).parent == tmp_path


def test_console_does_not_truncate_failures_or_errors(capsys):
    result = hardening.normalize_results(export(*[{"resource": str(i), "status": "alarm", "reason": "evidence"} for i in range(25)], error="Denied"), "aws", "target")
    hardening.print_hardening(result, target="target")
    output = capsys.readouterr().out
    assert output.count("| FAIL |") == 25
    assert "Checks that could not complete" in output
    assert output.count("#### Fixture") == 1


def test_native_worker_keeps_selected_credentials_and_cleans_runtime(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "host-role")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/host/credentials.json")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/host/aws-credentials")
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/host-role")
    monkeypatch.setattr(hardening.shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    adapter = SimpleNamespace(provider="kubernetes", probe=lambda: [{"allowed": True}],
        write=lambda root: hardening._write_config(root / "kubernetes.spc", 'config_path = "/input/kubeconfig.json"'))
    seen = []
    def execute(command, *, env, timeout):
        auth = Path(command[command.index("--input-dir") + 1])
        output = Path(command[command.index("--output-dir") + 1])
        runtime = Path(command[command.index("--work-dir") + 1])
        seen.append(runtime)
        runtime.mkdir()
        assert str(auth / "kubeconfig.json") in (auth / "kubernetes.spc").read_text()
        assert "AWS_ACCESS_KEY_ID" not in env
        assert "GOOGLE_APPLICATION_CREDENTIALS" not in env
        assert "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" not in env
        assert env["AWS_SHARED_CREDENTIALS_FILE"] == str(auth / "aws-shared-credentials")
        assert Path(env["AWS_SHARED_CREDENTIALS_FILE"]).read_text() == ""
        assert env["AWS_EC2_METADATA_DISABLED"] == "true"
        (output / "result.json").write_text(json.dumps(export({"resource": "pod", "status": "alarm", "reason": "configuration"})))
        return SimpleNamespace(returncode=0, stderr="")
    monkeypatch.setattr(hardening, "_run_native_worker", execute)
    result = hardening.run_hardening(options(hardening_runtime="native"), adapter, "cluster")
    assert result["summary"]["by_status"] == {"FAIL": 1}
    assert not seen[0].exists()
    assert hardening.os.environ["AWS_ACCESS_KEY_ID"] == "host-role"


def test_exhausted_hosted_budget_does_not_start_native_worker(monkeypatch):
    monkeypatch.setenv("BLUEPEASS_HARDENING_DEADLINE", "0")
    monkeypatch.setattr(hardening, "_run_native_worker", lambda *a, **k: pytest.fail("No execution budget"))
    adapter = SimpleNamespace(probe=lambda: pytest.fail("Queued target probed after the deadline"))
    result = hardening.run_hardening(options(hardening_runtime="native"), adapter, "target")
    assert result["status"] == "error"
    assert "budget exhausted" in result["reason"]


def test_native_timeout_retains_results_of_completed_suites(monkeypatch):
    monkeypatch.setattr(hardening.shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    adapter = SimpleNamespace(provider="aws", probe=lambda: [{"allowed": True}], write=lambda root: None)
    def execute(command, **kwargs):
        output = Path(command[command.index("--output-dir") + 1])
        (output / "result.json").write_text(json.dumps(export({"resource": "bucket", "status": "alarm", "reason": "configuration"})))
        raise hardening.subprocess.TimeoutExpired("worker", 1)
    monkeypatch.setattr(hardening, "_run_native_worker", execute)
    result = hardening.run_hardening(options(hardening_runtime="native"), adapter, "account")
    assert result["status"] == "partial"
    assert result["summary"]["by_status"] == {"FAIL": 1}
    assert not result["coverage"]["complete"]
    assert any("retained" in error["error"] for error in result["errors"])


def test_native_timeout_terminates_descendants(monkeypatch):
    process = SimpleNamespace(pid=4321, returncode=-15)
    calls = []
    def communicate(**kwargs):
        if not calls:
            calls.append("timeout")
            raise hardening.subprocess.TimeoutExpired("worker", 1)
        return "", ""
    process.communicate = communicate
    def popen(command, **kwargs):
        assert kwargs["start_new_session"] is True
        return process
    monkeypatch.setattr(hardening.subprocess, "Popen", popen)
    monkeypatch.setattr(hardening.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    with pytest.raises(hardening.subprocess.TimeoutExpired):
        hardening._run_native_worker(["worker"], env={}, timeout=1)
    assert (4321, hardening.signal.SIGTERM) in calls
    assert (4321, hardening.signal.SIGKILL) in calls


def test_report_summary_includes_hardening_coverage_errors():
    from bluepeass.report import build_report
    audit = hardening.normalize_results(export(error="Denied"), "aws", "target")
    report = build_report(provider="aws", targets=[{"data": {"errors": [], "hardening": audit}}])
    assert report["summary"]["target_errors"] == 1
    assert report["summary"]["errors"] == 1
    assert not report["summary"]["hardening"]["coverage_complete"]


@pytest.mark.parametrize("arguments", [
    ["--resource", "https://graph.microsoft.com/"],
    ["--scope", "https://graph.microsoft.com/.default"],
    ["--resource=https://graph.microsoft.com/"],
    ["--resource-type=ms-graph"],
])
def test_azure_sdk_cli_adapter_returns_the_requested_audience(tmp_path, monkeypatch, capsys, arguments):
    module = load_script("azure_credential_helper_test", "docker/credential_helper.py")
    monkeypatch.setenv("BLUEPEASS_AUTH_DIR", str(tmp_path))
    (tmp_path / "azure-tokens.json").write_text(json.dumps({"subscription": "selected-subscription", "tenant": "selected-tenant", "tokens": {
        "https://management.azure.com": {"token": "arm-token", "expires_on": 9999999999},
        "https://graph.microsoft.com": {"token": "graph-token", "expires_on": 9999999999},
    }}))
    assert module.main(["account", "get-access-token", *arguments]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["accessToken"] == "graph-token"
    assert result["tenant"] == "selected-tenant"


def test_azure_missing_audience_is_not_replaced_with_arm_token(tmp_path, monkeypatch, capsys):
    module = load_script("azure_missing_audience_test", "docker/credential_helper.py")
    monkeypatch.setenv("BLUEPEASS_AUTH_DIR", str(tmp_path))
    (tmp_path / "azure-tokens.json").write_text(json.dumps({"subscription": "sub", "tenant": "tenant", "tokens": {"https://management.azure.com": {"token": "private-token", "expires_on": 9999999999}}}))
    assert module.main(["account", "get-access-token", "--resource", "https://graph.microsoft.com"]) == 1
    captured = capsys.readouterr()
    assert "private-token" not in captured.out + captured.err
