"""Credential encryption and recursive evidence sanitization."""
import json
import os
from pathlib import Path
import re
import uuid
from cryptography.fernet import Fernet

SENSITIVE = re.compile(r"(?i)^(?:.*password|.*passwd|.*clientsecret|.*secretaccesskey|.*secret|secretvalue|(?:access|refresh|id|session|aws.?session|bearer|oauth|api|subject|federated)?token|authorization|privatekey|clientkey(?:data)?|apikey|keystring|(?:aws)?accesskeyid|credentials|credential|connectionstring|kubeconfig)$")


def private_file(path: Path, factory) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        return path.read_bytes()
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    value = factory()
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        try:
            os.link(temporary, path)
        except FileExistsError:
            value = path.read_bytes()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return value


class CredentialCipher:
    def __init__(self, identity_dir: Path):
        key = os.getenv("PEASO_ENCRYPTION_KEY")
        arn = os.getenv("PEASO_CREDENTIAL_SECRET_ARN")
        if arn:
            import boto3
            key = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"].strip()
        if os.getenv("PEASO_STORAGE") == "dynamodb" and not key:
            raise ValueError("Hosted storage requires a configured credential encryption key")
        self.fernet = Fernet(key.encode() if key else private_file(identity_dir / "credentials.key", Fernet.generate_key))

    def encrypt(self, value: dict) -> str:
        return self.fernet.encrypt(json.dumps(value, separators=(",", ":")).encode()).decode()

    def decrypt(self, value: str) -> dict:
        return json.loads(self.fernet.decrypt(value.encode()))


def secret_values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from secret_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from secret_values(item)
    elif isinstance(value, str) and value:
        yield value


PUBLIC_AUTH_FIELDS = {"provider", "method", "profile", "context", "region_name", "role_arn", "external_id", "target_principal", "impersonate_service_account", "tenant_id", "client_id", "account", "quota_project", "server", "cluster_id", "in_cluster", "session_name", "role_session_name", "token_uri", "client_email", "type", "project_id", "private_key_id", "auth_uri", "auth_provider_x509_cert_url", "client_x509_cert_url", "universe_domain", "name", "namespace", "current-context", "apiVersion", "kind"}


def credential_values(value):
    """Extract credentials without treating provider/method/identity names as secrets."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key in PUBLIC_AUTH_FIELDS:
                continue
            if isinstance(item, (dict, list)):
                yield from credential_values(item)
            elif key in {"sa_json", "external_account_json", "kubeconfig_data"} and isinstance(item, str):
                try:
                    parsed = json.loads(item)
                except (ValueError, TypeError):
                    import yaml
                    try:
                        parsed = yaml.safe_load(item)
                    except Exception:
                        parsed = None
                if parsed is not None:
                    yield from credential_values(parsed)
            elif isinstance(item, str) and item:
                yield item
    elif isinstance(value, list):
        for item in value:
            yield from credential_values(item)


def redact(value, secrets=()):
    """Drop secret-shaped fields and replace known credential values everywhere."""
    if isinstance(value, dict):
        labels = [item for key, item in value.items() if str(key).lower() in {"key", "name"} and isinstance(item, str)]
        paired_secret = any(SENSITIVE.fullmatch(re.sub(r"[^a-zA-Z0-9]", "", label)) for label in labels)
        return {str(k): "[REDACTED]" if (SENSITIVE.fullmatch(re.sub(r"[^a-zA-Z0-9]", "", str(k))) or (paired_secret and str(k).lower() in {"value", "content", "data"})) and isinstance(v, (str, dict, list)) else redact(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        value = re.sub(r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", value)
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret and (len(secret) >= 4 or value == secret):
                value = value.replace(secret, "[REDACTED]")
        return value
    return value
