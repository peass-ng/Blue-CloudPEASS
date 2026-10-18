import concurrent.futures
import json
import os
import threading
import uuid
import pytest

moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")
from peaso.storage.dynamodb import DynamoStore
from peaso.storage import StoreError, S3Artifacts


@pytest.fixture
def store():
    endpoint = os.getenv("PEASO_TEST_DYNAMODB_ENDPOINT")
    if endpoint:
        client = boto3.client("dynamodb", region_name="us-east-1", endpoint_url=endpoint, aws_access_key_id="localtest", aws_secret_access_key="localtest")
        name = "peaso-test-" + uuid.uuid4().hex
        client.create_table(TableName=name, KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}], AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}, {"AttributeName": "SK", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")
        try:
            instance = DynamoStore(name, client)
            instance.clock = lambda: 1000
            yield instance
        finally:
            client.delete_table(TableName=name)
        return
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="peaso", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}], AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}, {"AttributeName": "SK", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")
        # Moto's transaction deep-copy is not thread safe. Serialize individual
        # service calls to model atomic AWS requests, retaining interleaved store
        # operations; the real DynamoDB Local mode above verifies concurrency.
        lock = threading.RLock()
        class AtomicService:
            def __getattr__(self, name):
                operation = getattr(client, name)
                if not callable(operation):
                    return operation
                def call(*args, **kwargs):
                    with lock:
                        return operation(*args, **kwargs)
                return call
        instance = DynamoStore("peaso", AtomicService())
        instance.clock = lambda: 1000
        yield instance


@pytest.mark.parametrize("limit", [1, 10])
def test_dynamodb_quota_idempotency_and_tenant_isolation(store, limit):
    connector = store.add_connector("alice", {"provider": "aws"}, "ciphertext")
    request = {"connector_id": connector["id"]}
    first = store.enqueue("alice", request, limit=limit, idem="retry")
    assert store.enqueue("alice", request, limit=limit, idem="retry")["id"] == first["id"]
    for index in range(limit - 1):
        store.enqueue("alice", request, limit=limit, idem=str(index))
    with pytest.raises(StoreError) as error:
        store.enqueue("alice", request, limit=limit)
    assert error.value.status == 429 and store.usage("alice") == limit
    with pytest.raises(StoreError):
        store.job("bob", first["id"])
    with pytest.raises(StoreError):
        store.enqueue("bob", request)
    assert store.connectors("bob") == []


def test_dynamodb_claim_transition_fence_and_cancel(store):
    connector = store.add_connector("alice", {"provider": "aws"}, "ciphertext")
    job = store.enqueue("alice", {"connector_id": connector["id"]}, now=1000, timeout=100)
    first = store.claim("collector", lease_seconds=3, now=1001, tenant="alice", ident=job["id"])
    assert first and not store.claim("collector", now=1002)
    second = store.claim("collector", now=1005)
    assert second and second["owner"] != first["owner"]
    assert not store.finish(job["id"], first["owner"], "collected", "stale", now=1006)
    assert store.heartbeat(job["id"], second["owner"], now=1006)
    assert store.finish(job["id"], second["owner"], "collected", "snapshot-ref", now=1007)
    analyzer = store.claim("analyzer", now=1008)
    assert not store.finish(job["id"], analyzer["owner"], "collected", "bad", now=1009)
    store.cancel("alice", job["id"])
    assert not store.finish(job["id"], analyzer["owner"], "completed", "late", now=1009)
    assert store.public_job(store.job("alice", job["id"]))["timeline"][-1]["status"] == "cancelled"


@pytest.mark.parametrize("limit", [1, 10])
def test_dynamodb_concurrent_quota_transaction(store, limit):
    connector = store.add_connector("alice", {"provider": "aws"}, "ciphertext")
    def reserve(index):
        try:
            return store.enqueue("alice", {"connector_id": connector["id"]}, limit=limit, idem="concurrent-" + str(index))
        except StoreError as exc:
            return exc.status
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(reserve, range(24)))
    assert sum(isinstance(value, dict) for value in outcomes) == limit
    assert all(isinstance(value, dict) or value == 429 for value in outcomes)
    assert store.usage("alice") == limit


def test_dynamodb_concurrent_same_idempotency_key(store):
    connector = store.add_connector("alice", {"provider": "aws"}, "ciphertext")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: store.enqueue("alice", {"connector_id": connector["id"]}, idem="same-key"), range(16)))
    assert len({value["id"] for value in results}) == 1
    assert store.usage("alice") == 1


def test_dynamodb_scheduler_atomic_occurrence_and_shared_quota(store):
    connector = store.add_connector("alice", {"provider": "aws"}, "ciphertext")
    store.add_schedule("alice", {"connector_id": connector["id"], "interval_hours": 168}, 1000)
    due = store.due_schedules(1000)[0]
    assert store.trigger_schedule(due, now=1000)
    assert store.trigger_schedule(due, now=1000)["id"] == store.jobs("alice")[0]["id"]
    assert store.usage("alice", 1000) == 1
    store.update_schedule("alice", due["id"], {}, next_run=1001)
    assert store.trigger_schedule(store.due_schedules(1001)[0], now=1001) is None
    assert store.schedules("alice")[0]["last_error"] == "Weekly scan quota exhausted"


def test_dynamodb_deadline_and_entitlement_expiry(store):
    connector = store.add_connector("alice", {"provider": "aws"}, "ciphertext")
    job = store.enqueue("alice", {"connector_id": connector["id"]}, now=1000, timeout=1)
    store.expire(1002)
    assert store.job("alice", job["id"])["status"] == "timed_out"
    store.set_entitlement("alice", True)
    assert store.get_entitlement("alice") is True
    assert store.get_entitlement("bob") is None
    store.set_entitlement("alice", True, seconds=-1)
    assert store.get_entitlement("alice") is None


def test_pause_schedule_is_tenant_scoped_and_safe_after_deletion(store):
    connector = store.add_connector("alice", {"provider": "aws"}, "ciphertext")
    schedule = store.add_schedule("alice", {"connector_id": connector["id"], "interval_hours": 168}, 1000)
    assert store.pause_schedule("bob", schedule["id"]) is False
    assert store.schedules("alice")[0]["enabled"] is True
    assert store.pause_schedule("alice", schedule["id"]) is True
    assert store.schedules("alice")[0]["enabled"] is False
    store.delete_schedule("alice", schedule["id"])
    assert store.pause_schedule("alice", schedule["id"]) is False
    assert store.schedules("alice") == [] and store.schedules("bob") == []


def test_s3_artifacts_private_encryption_and_tenant_references():
    with moto.mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="peaso-private")
        storage = S3Artifacts("peaso-private", client)
        reference = storage.put("alice", "a" * 32, "report", {"test": True})
        assert storage.get("alice", reference) == {"test": True}
        head = client.head_object(Bucket="peaso-private", Key="artifacts/" + reference)
        assert head["ServerSideEncryption"] == "AES256"
        with pytest.raises(ValueError):
            storage.get("bob", reference)
        with pytest.raises(ValueError):
            storage.get("alice", "../secret")
