"""Narrow hosted Azure token field: encrypted credentials and evidence redaction."""
from types import SimpleNamespace
from cryptography.fernet import Fernet
from fastapi import HTTPException
import pytest
from peaso.auth.secrets import CredentialCipher, credential_values, redact
from peaso.server.validation import validate_connector


@pytest.mark.parametrize("field", ["vault_token", "storage_token"])
def test_optional_vault_audience_token_is_accepted_with_explicit_arm_auth(field):
    settings = SimpleNamespace(auth_mode="cognito")
    for optional in ({}, {field: "PRIVATE_AUDIENCE_SENTINEL"}):
        auth = {"method": "token", "arm_token": "ARM_PRIVATE_SENTINEL", **optional}
        validate_connector("azure", auth, {}, settings)


@pytest.mark.parametrize("invalid", [123, {}, "x" * 1_000_001])
@pytest.mark.parametrize("field", ["vault_token", "storage_token"])
def test_invalid_vault_token_shape_is_rejected_without_provider_calls(invalid, field):
    with pytest.raises(HTTPException) as failure:
        validate_connector("azure", {"method": "token", "arm_token": "fixture", field: invalid}, {}, SimpleNamespace(auth_mode="cognito"))
    assert failure.value.status_code == 422
    assert "fixture" not in str(failure.value.detail)


@pytest.mark.parametrize("field", ["vault_token", "storage_token"])
def test_vault_token_is_encrypted_and_redacted_from_arbitrary_evidence(monkeypatch, tmp_path, field):
    monkeypatch.delenv("PEASO_CREDENTIAL_SECRET_ARN", raising=False)
    monkeypatch.setenv("PEASO_ENCRYPTION_KEY", Fernet.generate_key().decode())
    auth = {"method": "token", "arm_token": "ARM_PRIVATE_SENTINEL", field: "VAULT_PRIVATE_SENTINEL"}
    cipher = CredentialCipher(tmp_path)
    encrypted = cipher.encrypt(auth)
    assert "VAULT_PRIVATE_SENTINEL" not in encrypted
    assert cipher.decrypt(encrypted) == auth
    assert "VAULT_PRIVATE_SENTINEL" in set(credential_values(auth))
    assert redact({field: "VAULT_PRIVATE_SENTINEL"})[field] == "[REDACTED]"
    assert "VAULT_PRIVATE_SENTINEL" not in str(redact({"message": "VAULT_PRIVATE_SENTINEL"}, credential_values(auth)))
