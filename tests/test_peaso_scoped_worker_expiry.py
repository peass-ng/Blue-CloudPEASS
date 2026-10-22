"""Offline scoped expiry contracts: real stores, fenced races, and worker paths."""
from unittest.mock import patch

import boto3
import moto
import pytest
from botocore.exceptions import ClientError

from peaso.auth import CredentialCipher
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore, StoreError
from peaso.storage.dynamodb import DynamoStore, attrs
from peaso.worker import Worker


@pytest.fixture(params=["sqlite", "dynamodb"])
def store(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteStore(tmp_path / "state")
        return
    yield request.getfixturevalue("dynamo_store")


@pytest.fixture
def dynamo_store():
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="peaso", BillingMode="PAY_PER_REQUEST",
                            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": name, "AttributeType": "S"} for name in ("PK", "SK")])
        instance = DynamoStore("peaso", client)
        instance.clock = lambda: 1000
        yield instance


def enqueue(store, tenant="alice", timeout=10, auth="ciphertext"):
    connector = store.add_connector(tenant, {"provider": "aws"}, auth)
    job = store.enqueue(tenant, {"connector_id": connector["id"]}, now=1000, timeout=timeout, limit=10)
    # These cases exercise the execution deadline after a scan slot is granted.
    assert store.admit(tenant, job["id"], now=1000)
    return job


def no_global_expiry(store, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Scoped worker reached global expiry or Scan")
    monkeypatch.setattr(store, "expire", forbidden)
    if isinstance(store, DynamoStore):
        monkeypatch.setattr(store.client, "scan", forbidden)


@pytest.mark.parametrize("status", ["queued", "collecting", "collected", "analyzing", "completed", "failed", "cancelled", "timed_out"])
def test_expire_job_boundary_terminal_and_isolation(store, monkeypatch, status):
    target = enqueue(store)
    sibling = enqueue(store)
    other = enqueue(store, "bob")
    if isinstance(store, DynamoStore):
        store.client.update_item(TableName=store.table, Key=attrs(store.key("alice", "job", target["id"])),
                                 UpdateExpression="SET #s=:s, #o=:o, lease=:lease",
                                 ExpressionAttributeNames={"#s": "status", "#o": "owner"},
                                 ExpressionAttributeValues=attrs({":s": status, ":o": "owner", ":lease": 2000}))
    else:
        with store.transaction() as db:
            db.execute("UPDATE jobs SET status=?,owner='owner',lease=2000 WHERE id=?", (status, target["id"]))
    before = store.job("alice", target["id"])
    siblings = [store.job("alice", sibling["id"]), store.job("bob", other["id"])]
    no_global_expiry(store, monkeypatch)
    assert store.expire_job("alice", target["id"], 1009) is False
    assert store.job("alice", target["id"]) == before
    terminal = status in {"completed", "failed", "cancelled", "timed_out"}
    assert store.expire_job("alice", target["id"], 1010) is (not terminal)
    current = store.job("alice", target["id"])
    if terminal:
        assert current == before
    else:
        assert current["status"] == "timed_out"
        assert current["owner"] is None and current["lease"] is None
        assert current["error"] == "Scan deadline exceeded"
        assert current["error_code"] == "deadline_exceeded"
        assert current["error_stage"] == ("collector" if status in {"queued", "collecting"} else "analyzer")
        assert store.public_job(current)["timeline"][-1] == {"status": "timed_out", "at": "1970-01-01T00:16:50+00:00"}
        assert store.expire_job("alice", target["id"], 1010) is False
        assert store.job("alice", target["id"]) == current
    assert [store.job("alice", sibling["id"]), store.job("bob", other["id"])] == siblings


@pytest.mark.parametrize("ident", ["missing", ""])
def test_wrong_tenant_and_missing_jobs_never_scan(store, monkeypatch, ident):
    target = enqueue(store)
    before = store.job("alice", target["id"])
    no_global_expiry(store, monkeypatch)
    for operation in (lambda: store.expire_job("bob", target["id"], 1010),
                      lambda: store.expire_job("alice", ident, 1010),
                      lambda: store.claim("collector", tenant="bob", ident=target["id"], now=1010),
                      lambda: store.claim("collector", tenant="alice", ident=ident, now=1010)):
        with pytest.raises(StoreError) as exc:
            operation()
        assert exc.value.status == 404
    assert store.job("alice", target["id"]) == before


@pytest.mark.parametrize("expired", [False, True])
@pytest.mark.parametrize("role", ["collector", "analyzer"])
def test_targeted_claim_expires_only_target(store, monkeypatch, role, expired):
    target = enqueue(store, timeout=10 if expired else 100)
    sibling = enqueue(store)
    other = enqueue(store, "bob")
    if role == "analyzer":
        claim = store.claim("collector", tenant="alice", ident=target["id"], now=1001)
        assert store.finish(target["id"], claim["owner"], "collected", "snapshot", now=1002)
    siblings = [store.job("alice", sibling["id"]), store.job("bob", other["id"])]
    no_global_expiry(store, monkeypatch)
    result = store.claim(role, tenant="alice", ident=target["id"], now=1010)
    if expired:
        assert result is None
        assert store.job("alice", target["id"])["status"] == "timed_out"
    else:
        assert result["status"] == ("collecting" if role == "collector" else "analyzing")
    assert [store.job("alice", sibling["id"]), store.job("bob", other["id"])] == siblings


@pytest.mark.parametrize("role", ["collector", "analyzer"])
def test_scoped_claim_reclaim_and_late_writes_are_fenced(store, monkeypatch, role):
    target = enqueue(store, timeout=100)
    if role == "analyzer":
        collector = store.claim("collector", tenant="alice", ident=target["id"], now=1001)
        assert store.finish(target["id"], collector["owner"], "collected", "snapshot", now=1002)
    no_global_expiry(store, monkeypatch)
    first = store.claim(role, 3, now=1003, tenant="alice", ident=target["id"])
    assert store.claim(role, now=1005, tenant="alice", ident=target["id"]) is None
    second = store.claim(role, 3, now=1006, tenant="alice", ident=target["id"])
    assert second["owner"] != first["owner"]
    status = "collected" if role == "collector" else "completed"
    assert not store.heartbeat(target["id"], first["owner"], now=1007)
    assert not store.finish(target["id"], first["owner"], status, "stale", now=1007)
    assert store.heartbeat(target["id"], second["owner"], now=1007)
    assert store.expire_job("alice", target["id"], 1100)
    assert not store.heartbeat(target["id"], second["owner"], now=1100)
    assert not store.finish(target["id"], second["owner"], status, "late", now=1100)


def test_global_expiry_remains_available(store):
    first, second = enqueue(store), enqueue(store, "bob")
    store.expire(1010)
    assert store.job("alice", first["id"])["status"] == "timed_out"
    assert store.job("bob", second["id"])["status"] == "timed_out"


@pytest.mark.parametrize("mutation", ["cancelled", "completed", "stage", "deadline", "deleted"])
def test_dynamo_expiry_read_update_races_preserve_concurrent_row(dynamo_store, monkeypatch, mutation):
    store = dynamo_store
    target = enqueue(store)
    original = store.client.update_item
    raced = []
    def update(**kwargs):
        if not raced:
            raced.append(True)
            key = attrs(store.key("alice", "job", target["id"]))
            if mutation == "deleted":
                store.client.delete_item(TableName=store.table, Key=key)
            elif mutation == "deadline":
                original(TableName=store.table, Key=key, UpdateExpression="SET deadline=:deadline", ExpressionAttributeValues=attrs({":deadline": 2000}))
            else:
                original(TableName=store.table, Key=key, UpdateExpression="SET #s=:s", ExpressionAttributeNames={"#s": "status"},
                         ExpressionAttributeValues=attrs({":s": "collected" if mutation == "stage" else mutation}))
        return original(**kwargs)
    no_global_expiry(store, monkeypatch)
    with patch.object(store.client, "get_item", wraps=store.client.get_item) as get:
        monkeypatch.setattr(store.client, "update_item", update)
        assert store.expire_job("alice", target["id"], 1010) is False
        assert get.call_count == 1 and get.call_args.kwargs["ConsistentRead"] is True
        assert get.call_args.kwargs["Key"] == attrs(store.key("alice", "job", target["id"]))
    assert raced
    if mutation == "deleted":
        assert store._get("alice", "job", target["id"]) is None
    else:
        current = store.job("alice", target["id"])
        assert current["error_code"] is None
        assert current["status"] == ("queued" if mutation == "deadline" else "collected" if mutation == "stage" else mutation)
        if mutation == "stage":
            assert store.expire_job("alice", target["id"], 1010)
            assert store.job("alice", target["id"])["error_stage"] == "analyzer"


def test_dynamo_expiry_service_failure_is_not_suppressed(dynamo_store, monkeypatch):
    store = dynamo_store
    target = enqueue(store)
    def fail(**kwargs):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "fixture"}}, "UpdateItem")
    no_global_expiry(store, monkeypatch)
    monkeypatch.setattr(store.client, "update_item", fail)
    with pytest.raises(ClientError, match="AccessDeniedException"):
        store.expire_job("alice", target["id"], 1010)
    assert store.job("alice", target["id"])["status"] == "queued"


@pytest.mark.parametrize("role", ["collector", "analyzer"])
@pytest.mark.parametrize("outcome", ["success", "failure", "timeout", "cancel-at-timeout"])
def test_run_once_scoped_success_failure_timeout_and_cleanup(store, monkeypatch, tmp_path, role, outcome):
    clock = [1001]
    monkeypatch.setattr("peaso.worker.time.time", lambda: clock[0])
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    cipher = CredentialCipher(settings.identity_dir)
    target = enqueue(store, auth=cipher.encrypt({"auth": {}, "options": {}}))
    other = enqueue(store, "bob", timeout=1)
    sibling = enqueue(store, timeout=1)
    if role == "analyzer":
        claim = store.claim("collector", tenant="alice", ident=target["id"])
        assert store.finish(target["id"], claim["owner"], "collected", "snapshot")
    unrelated = [store.job("bob", other["id"]), store.job("alice", sibling["id"])]
    closed, processes = [], []
    class Connection:
        def close(self):
            closed.append(self)
        def poll(self, timeout):
            return True
        def recv(self):
            return (True, "artifact") if outcome == "success" else (False, "provider_error")
    class Process:
        def __init__(self, **kwargs):
            self.alive = False
            self.terminated = False
            self.joined = False
            processes.append(self)
        def start(self):
            self.alive = True
            if outcome in {"timeout", "cancel-at-timeout"}:
                clock[0] = 1010
            if outcome == "cancel-at-timeout":
                store.cancel("alice", target["id"])
        def is_alive(self):
            return self.alive
        def terminate(self):
            self.alive = False
            self.terminated = True
        def join(self, timeout):
            self.joined = True
    class Context:
        @staticmethod
        def Pipe(duplex):
            return Connection(), Connection()
    Context.Process = Process
    monkeypatch.setattr("peaso.worker.multiprocessing.get_context", lambda _: Context())
    no_global_expiry(store, monkeypatch)
    assert Worker(role, settings, store=store, artifacts=FileArtifacts(tmp_path / "artifacts")).run_once("alice", target["id"])
    current = store.job("alice", target["id"])
    expected = {"success": "collected" if role == "collector" else "completed", "failure": "failed", "timeout": "timed_out", "cancel-at-timeout": "cancelled"}[outcome]
    assert current["status"] == expected
    assert current["owner"] is None and current["lease"] is None
    if outcome in {"timeout", "failure"}:
        assert current["error_code"] == ("deadline_exceeded" if outcome == "timeout" else "provider_error")
        assert current["error_stage"] == role
    assert [store.job("bob", other["id"]), store.job("alice", sibling["id"])] == unrelated
    assert all(p.terminated and p.joined and not p.is_alive() for p in processes)
    assert len(set(closed)) == 2


@pytest.mark.parametrize("role", ["collector", "analyzer"])
@pytest.mark.parametrize("mutation", ["competing-claim", "cancelled", "deadline"])
def test_dynamo_targeted_claim_read_update_race(dynamo_store, monkeypatch, role, mutation):
    store = dynamo_store
    target = enqueue(store, timeout=100)
    if role == "analyzer":
        collector = store.claim("collector", tenant="alice", ident=target["id"], now=1001)
        assert store.finish(target["id"], collector["owner"], "collected", "snapshot", now=1002)
    original = store.client.update_item
    raced, winner = [], []
    def update(**kwargs):
        if not raced:
            raced.append(True)
            if mutation == "competing-claim":
                winner.append(store.claim(role, tenant="alice", ident=target["id"], now=1003))
            elif mutation == "cancelled":
                store.cancel("alice", target["id"])
            else:
                original(TableName=store.table, Key=attrs(store.key("alice", "job", target["id"])),
                         UpdateExpression="SET deadline=:deadline", ExpressionAttributeValues=attrs({":deadline": 1003}))
        return original(**kwargs)
    no_global_expiry(store, monkeypatch)
    monkeypatch.setattr(store.client, "update_item", update)
    assert store.claim(role, tenant="alice", ident=target["id"], now=1003) is None
    assert raced
    current = store.job("alice", target["id"])
    if mutation == "competing-claim":
        assert winner[0]["owner"] == current["owner"]
        assert current["status"] == ("collecting" if role == "collector" else "analyzing")
        assert len([event for event in current["history"] if event["status"] == current["status"]]) == 1
    elif mutation == "cancelled":
        assert current["status"] == "cancelled" and current["owner"] is None
    else:
        assert current["deadline"] == 1003 and current["owner"] is None
