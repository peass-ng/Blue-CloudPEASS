"""Protected operator scan quota must be fenced inside the reservation transaction."""
import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from peaso.storage import StoreError
from peaso.storage.dynamodb import DynamoStore, attrs


TENANT = "subject-123"


class RecordingClient:
    def __init__(self, client):
        self.client = client
        self.transactions = []
        self.before_transaction = None

    def __getattr__(self, name):
        return getattr(self.client, name)

    def transact_write_items(self, **kwargs):
        self.transactions.append(kwargs["TransactItems"])
        if self.before_transaction:
            callback, self.before_transaction = self.before_transaction, None
            callback()
        return self.client.transact_write_items(**kwargs)


@pytest.fixture
def hosted():
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="operator-quota-test",
                            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                                       {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                                  {"AttributeName": "SK", "AttributeType": "S"}],
                            BillingMode="PAY_PER_REQUEST")
        recording = RecordingClient(client)
        store = DynamoStore("operator-quota-test", recording)
        connector = store.add_connector(TENANT, {"provider": "aws"}, "ciphertext")
        yield store, recording, client, {"connector_id": connector["id"]}


def grant(store, **changes):
    value = {"PK": "tenant/" + TENANT, "SK": "operator_scan_quota",
             "kind": "operator_scan_quota", "tenant": TENANT, "cognito_subject": TENANT,
             "unlimited": True, "verified_email": "operator@example.test",
             "cognito_pool_id": "eu-west-1_example", "actor": "arn:aws:sts::123456789012:assumed-role/operator/session",
             "reason": "operator request", "created": 1000, "audit_id": "run-123"}
    value.update(changes)
    store.client.put_item(TableName=store.table, Item=attrs(value))
    return value


def test_valid_grant_fences_transaction_and_preserves_usage(hosted):
    store, recording, _, request = hosted
    grant(store)
    assert store.unlimited_scans(TENANT)
    first = store.enqueue(TENANT, request, limit=1, idem="same-request")
    assert store.enqueue(TENANT, request, limit=1, idem="same-request")["id"] == first["id"]
    store.enqueue(TENANT, request, limit=1)
    assert store.usage(TENANT) == 2
    transaction = recording.transactions[-1]
    quota = transaction[1]["Update"]
    assert "ConditionExpression" not in quota
    assert "ADD used :one" in quota["UpdateExpression"]
    fence = next(item["ConditionCheck"] for item in transaction if "ConditionCheck" in item and
                 item["ConditionCheck"]["Key"]["SK"] == {"S": "operator_scan_quota"})
    assert all(name in fence["ExpressionAttributeNames"].values() for name in
               ("kind", "tenant", "cognito_subject", "unlimited", "audit_id"))
    assert fence["ExpressionAttributeValues"][":audit_id"] == {"S": "run-123"}


@pytest.mark.parametrize("change", [
    {"kind": "other"}, {"tenant": "other"}, {"cognito_subject": "other"},
    {"unlimited": False}, {"unlimited": 1}, {"audit_id": ""},
    {"verified_email": ""}, {"created": "yesterday"},
])
def test_malformed_grant_fails_closed_and_normal_quota_remains(hosted, change):
    store, _, _, request = hosted
    grant(store, **change)
    assert not store.unlimited_scans(TENANT)
    store.enqueue(TENANT, request, limit=1)
    with pytest.raises(StoreError) as error:
        store.enqueue(TENANT, request, limit=1)
    assert error.value.status == 429
    assert store.usage(TENANT) == 1


def test_revocation_between_read_and_transaction_fails_closed(hosted):
    store, recording, client, request = hosted
    grant(store)
    store.enqueue(TENANT, request, limit=1)

    def revoke():
        client.delete_item(TableName=store.table,
                           Key=attrs({"PK": "tenant/" + TENANT, "SK": "operator_scan_quota"}))

    recording.before_transaction = revoke
    with pytest.raises(StoreError) as error:
        store.enqueue(TENANT, request, limit=1)
    assert error.value.status == 429
    assert not store.unlimited_scans(TENANT)
    assert store.usage(TENANT) == 1
    assert len(store.jobs(TENANT)) == 1


def test_me_exposes_protected_override_without_changing_plan(hosted, tmp_path):
    from fastapi.testclient import TestClient
    from peaso.auth import Identity
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.storage import FileArtifacts

    class IdentityProvider:
        def authenticate(self, authorization):
            return Identity(TENANT)

    store, _, _, _ = hosted
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
                        auth_mode="local")
    app = create_app(settings, store=store, authenticator=IdentityProvider(),
                     artifacts=FileArtifacts(tmp_path / "artifacts"))
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        normal = client.get("/api/me").json()
        assert normal["weekly_limit"] == 1 and normal["weekly_unlimited"] is False
        grant(store)
        enabled = client.get("/api/me").json()
        assert enabled["weekly_limit"] is None and enabled["weekly_unlimited"] is True
        assert enabled["plan"] == normal["plan"] == "free"
