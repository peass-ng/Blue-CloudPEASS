"""Historical scan labels use frozen identity metadata, never credentials."""
from datetime import datetime, timezone
import json

from fastapi.testclient import TestClient
import pytest

from peaso.auth.secrets import CredentialCipher
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.server.scan_names import display_name, identity_hint
from peaso.storage import SQLiteStore, FileArtifacts
from tests.test_peaso_findings_sorting import Identities

WHEN = datetime(2026, 10, 18, 8, 11, tzinfo=timezone.utc).timestamp()


@pytest.mark.parametrize("provider,auth,scopes,expected", [
    ("aws", {"role_arn": "arn:aws:iam::123456789098:role/security/ReadOnly"},
     ["123456789098/us-east-1", "123456789098/eu-west-1"], "aws-ReadOnly-123456789098-18.10.26"),
    ("gcp", {"sa_json": {"client_email": "security-reader@my-project.iam.gserviceaccount.com", "project_id": "my-project", "private_key": "PRIVATE-KEY-MARKER"}},
     ["projects/my-project"], "gcp-security-reader-my-project-18.10.26"),
    ("azure", {"client_id": "abcdef01-2345-6789-abcd-123456789012", "client_secret": "CLIENT-SECRET-MARKER"},
     ["/subscriptions/12345678-abcd-abcd-abcd-123456789012"], "azure-abcdef01-12345678-18.10.26"),
    ("k8s", {"kubeconfig_data": "current-context: production\ncontexts:\n- name: production\n  context:\n    user: security-reader\n    cluster: prod-cluster\nusers:\n- name: security-reader\n  user:\n    token: SECRET-TOKEN-MARKER\n"},
     ["*"], "k8s-security-reader-prod-cluster-18.10.26"),
])
def test_all_cloud_names_and_regional_account_deduplication(provider, auth, scopes, expected):
    assert display_name({"created_at": "2026-10-18T08:11:00Z"},
                        {"provider": provider, "name": "connector", "scopes": scopes},
                        identity_hint(provider, {"auth": auth})) == expected


def test_multiple_account_scan_is_not_named_as_one_account():
    hint = identity_hint("aws", {"auth": {"assume_roles": [
        {"role_arn": "arn:aws:iam::123456789098:role/ReadOnly"},
        {"role_arn": "arn:aws:iam::123456789099:role/ReadOnly"}]}})
    assert display_name({"created_at": "2026-10-18"}, {"provider": "aws"}, hint) == "aws-ReadOnly-2-accounts-18.10.26"


def test_selected_account_uses_its_role_not_other_configured_targets():
    hint = identity_hint("aws", {"auth": {"assume_roles": [
        {"role_arn": "arn:aws:iam::123456789098:role/SelectedRole"},
        {"role_arn": "arn:aws:iam::123456789099:role/OtherRole"}]}}, ["123456789098/us-east-1"])
    assert hint == ("SelectedRole", ["123456789098"], None)


def test_opaque_credentials_are_never_used_as_identity_names():
    private = {"auth": {"aws_access_key_id": "KEY-MARKER", "aws_secret_access_key": "SECRET-MARKER", "token": "TOKEN-MARKER"}}
    for provider in ("aws", "gcp", "azure", "k8s"):
        value = display_name({"created_at": "2026-10-18"}, {"provider": provider, "name": "read-only", "scopes": ["target"]}, identity_hint(provider, private))
        assert "MARKER" not in value


def test_imported_scan_uses_recorded_target_role_not_default_or_source_identity():
    private = {"auth": {"method": "default"}, "options": {"snapshot": {"metadata": {"caller_identities": [
        {"Account": "202533532952", "Arn": "arn:aws:sts::202533532952:assumed-role/Platform/session"},
        {"Account": "123456789098", "Arn": "arn:aws:sts::123456789098:assumed-role/pentest-readonly/session"},
    ]}}}}
    scopes = ["123456789098/us-east-1", "123456789098/eu-west-1"]
    assert display_name({"created_at": "2026-10-18"}, {"provider": "aws", "scopes": scopes},
                        identity_hint("aws", private, scopes)) == "aws-pentest-readonly-123456789098-18.10.26"


def test_list_and_detail_keep_frozen_identity_after_connector_deletion(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    cipher = CredentialCipher(settings.identity_dir)
    store = SQLiteStore(settings.state_dir)
    encrypted = cipher.encrypt({"auth": {"role_arn": "arn:aws:iam::123456789098:role/ReadOnly", "external_id": "SECRET-EXTERNAL-MARKER"},
                                "options": {"snapshot": {"private": "PRIVATE-SNAPSHOT-MARKER"}}})
    connector = store.add_connector("alice", {"provider": "aws", "name": "Old connector", "scopes": ["123456789098/us-east-1"]}, encrypted)
    scan = store.enqueue("alice", {"connector_id": connector["id"]}, now=WHEN)
    store.enqueue("alice", {"connector_id": connector["id"]}, now=WHEN + 1, limit=2)
    store.delete_connector("alice", connector["id"])
    with TestClient(create_app(settings, store=store, artifacts=FileArtifacts(settings.state_dir / "artifacts"), authenticator=Identities()), base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer alice"
        detail = client.get(f"/api/scans/{scan['id']}")
        assert detail.status_code == 200
        assert detail.json()["display_name"] == "aws-ReadOnly-123456789098-18.10.26"
        # Naming must not turn the list into one database lookup per scan.
        monkeypatch.setattr(store, "job", lambda *args: pytest.fail("Unexpected extra job lookup"))
        original = CredentialCipher.decrypt
        decryptions = []
        def counted_decrypt(self, value):
            decryptions.append(value)
            return original(self, value)
        monkeypatch.setattr(CredentialCipher, "decrypt", counted_decrypt)
        listed = client.get("/api/scans")
        assert listed.status_code == 200
        assert listed.json()["items"][0]["display_name"] == detail.json()["display_name"]
        assert scan["id"] in {item["id"] for item in listed.json()["items"]}
        assert decryptions == [encrypted]
        assert "MARKER" not in json.dumps(listed.json())
        client.headers["Authorization"] = "Bearer bob"
        assert client.get("/api/scans").json() == {"items": []}
