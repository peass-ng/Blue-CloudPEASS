"""Actual google-auth credential classes, with offline OAuth/STS/IAM transports.

No cloud key or IAM resource is created: the RSA key exists only in this fixture.
These tests prove SDK protocol integration, never live identity authorization.
"""
import json
from urllib.parse import urlsplit

import pytest

from peaso.collectors import gcp


class Reply:
    def __init__(self, value, status=200, content_type="application/json"):
        self.status = status
        self.data = (json.dumps(value) if content_type == "application/json" else value).encode()
        self.headers = {"content-type": content_type}


@pytest.fixture
def sa_info():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {"type": "service_account", "project_id": "fixture-project",
            "private_key_id": "fixture-key", "private_key": key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode(),
            "client_email": "fixture@fixture-project.iam.gserviceaccount.com",
            "client_id": "123", "token_uri": "https://oauth2.googleapis.com/token"}


def auth_input(method, sa_info, tmp_path):
    if method == "adc":
        path = tmp_path / "adc.json"
        path.write_text(json.dumps({"type": "authorized_user", "client_id": "fixture-client",
                                  "client_secret": "fixture-secret", "refresh_token": "fixture-refresh"}))
        path.chmod(0o600)
        return {"method": method}, path
    if method == "service-account":
        return {"method": method, "sa_json": sa_info}, None
    if method == "external-account":
        return {"method": method, "external_account_json": {
            "type": "external_account", "audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/fixture/providers/fixture",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://sts.googleapis.com/v1/token"}, "subject_token": "fixture-subject"}, None
    if method == "impersonation":
        return {"method": method, "source_auth": {"method": "service-account", "sa_json": sa_info},
                "target_principal": "target@fixture-project.iam.gserviceaccount.com",
                "delegates": ["projects/-/serviceAccounts/first@fixture-project.iam.gserviceaccount.com",
                              "projects/-/serviceAccounts/second@fixture-project.iam.gserviceaccount.com"]}, None
    raise AssertionError(method)


@pytest.mark.parametrize("method", ["adc", "service-account", "external-account", "impersonation"])
@pytest.mark.parametrize("denied", [False, True])
def test_selected_sdk_exchange_success_or_denial_never_falls_back(monkeypatch, tmp_path, sa_info, method, denied):
    from google.auth.transport.requests import Request
    auth, adc = auth_input(method, sa_info, tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(adc or tmp_path / "absent-adc.json"))
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "fixture-project")
    monkeypatch.setattr(gcp, "_gcloud", lambda *a: pytest.fail("unselected gcloud authentication"))
    calls = []

    def exchange(self, url, method="GET", body=None, headers=None, **kwargs):
        calls.append({"url": url, "method": method, "body": body})
        assert kwargs["timeout"] <= 7
        host = urlsplit(url).hostname
        assert host in {"oauth2.googleapis.com", "sts.googleapis.com", "iamcredentials.googleapis.com"}
        is_final = host == "iamcredentials.googleapis.com" if method_name == "impersonation" else True
        if denied and is_final:
            return Reply({"error": "access_denied", "error_description": "fixture-secret fixture-subject fixture-refresh"}, 403)
        if host == "iamcredentials.googleapis.com":
            request = json.loads(body)
            assert request["delegates"] == ["projects/-/serviceAccounts/first@fixture-project.iam.gserviceaccount.com",
                                           "projects/-/serviceAccounts/second@fixture-project.iam.gserviceaccount.com"]
            assert request["scope"] == gcp.OAUTH_SCOPES
            return Reply({"accessToken": "fixture-issued-token", "expireTime": "2099-01-01T00:00:00Z"})
        if host == "sts.googleapis.com":
            assert b"fixture-subject" in body
            return Reply({"access_token": "fixture-issued-token", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                          "token_type": "Bearer", "expires_in": 3600})
        assert b"grant_type=" in body
        return Reply({"access_token": "fixture-issued-token", "token_type": "Bearer", "expires_in": 3600})

    method_name = method
    monkeypatch.setattr(Request, "__call__", exchange)
    credentials = gcp.Credentials(auth, timeout=7)
    try:
        if denied:
            for _ in range(2):
                with pytest.raises(gcp.ReadError) as caught:
                    credentials.headers()
                assert caught.value.error == {"code": "credential_refresh_failed"}
                assert "fixture-" not in str(caught.value)
        else:
            assert {k.lower(): v for k, v in credentials.headers().items()}["authorization"] == "Bearer fixture-issued-token"
            assert {k.lower(): v for k, v in credentials.headers().items()}["authorization"] == "Bearer fixture-issued-token"
        assert len(calls) == (2 if method == "impersonation" else 1)
        hosts = [urlsplit(call["url"]).hostname for call in calls]
        assert hosts == (["oauth2.googleapis.com", "iamcredentials.googleapis.com"] if method == "impersonation"
                         else ["sts.googleapis.com"] if method == "external-account" else ["oauth2.googleapis.com"])
    finally:
        credentials.close()


def test_absent_selected_adc_is_redacted_and_does_not_use_logged_in_gcloud(monkeypatch, tmp_path):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "absent-private-credential.json"))
    monkeypatch.setattr(gcp, "_gcloud", lambda *args: pytest.fail("ADC failure fell back to gcloud"))
    result = gcp.collect({"provider": "gcp", "scopes": ["fixture-project"], "auth": {"method": "adc"},
                          "options": {"inventories": ["network"], "include_inherited": False, "retries": 0}})
    assert result["collections"][0]["status"] == "denied"
    assert result["collections"][0]["error"]["code"] == "credential_initialization_failed"
    assert "absent-private" not in json.dumps(result)


def test_gcloud_refresh_is_pinned_even_with_conflicting_process_defaults(monkeypatch):
    monkeypatch.setenv("CLOUDSDK_CORE_ACCOUNT", "other@example.invalid")
    monkeypatch.setenv("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "other-target@example.invalid")
    calls = []
    def command(args, env):
        calls.append((args, env))
        assert env["CLOUDSDK_CORE_ACCOUNT"] == "selected@example.invalid"
        assert env["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"] == ""
        assert "--impersonate-service-account" not in args
        return "fixture-issued-token"
    monkeypatch.setattr(gcp, "_gcloud", command)
    credentials = gcp.Credentials({"method": "gcloud", "account": "selected@example.invalid", "impersonate_service_account": ""})
    try:
        credentials.headers()
        credentials.gcloud.expires = 0
        credentials.headers()
        assert len(calls) == 2
        assert all(args[args.index("--account") + 1] == "selected@example.invalid" for args, env in calls)
    finally:
        credentials.close()


@pytest.mark.parametrize("denied", [False, True])
def test_metadata_sdk_reads_only_selected_account_and_redacts_failure(monkeypatch, denied):
    import google.auth
    from google.auth.transport.requests import Request
    monkeypatch.setattr(google.auth, "default", lambda **kw: pytest.fail("metadata failure fell back to ADC"))
    monkeypatch.setattr(gcp, "_gcloud", lambda *a: pytest.fail("metadata failure fell back to gcloud"))
    calls = []
    def metadata(self, url, method="GET", headers=None, **kwargs):
        calls.append(url)
        assert urlsplit(url).hostname in {"metadata.google.internal", "169.254.169.254"}
        assert kwargs["timeout"] <= 5
        if denied:
            return Reply("fixture-sensitive-server-body", 403, "text/plain")
        if "universe-domain" in url:
            return Reply("googleapis.com", content_type="text/plain")
        if "/token" in url:
            return Reply({"access_token": "fixture-metadata-token", "expires_in": 3600, "token_type": "Bearer"})
        assert "/service-accounts/selected@example.invalid/" in url
        return Reply({"email": "selected@example.invalid", "scopes": gcp.OAUTH_SCOPES})
    monkeypatch.setattr(Request, "__call__", metadata)
    credentials = gcp.Credentials({"method": "metadata", "service_account_email": "selected@example.invalid"}, timeout=5)
    try:
        if denied:
            with pytest.raises(gcp.ReadError) as caught:
                credentials.headers()
            assert caught.value.error == {"code": "credential_refresh_failed"}
            assert "fixture-sensitive" not in str(caught.value)
        else:
            headers = {k.lower(): v for k, v in credentials.headers().items()}
            assert headers["authorization"] == "Bearer fixture-metadata-token"
            assert any("/token" in url for url in calls)
    finally:
        credentials.close()
