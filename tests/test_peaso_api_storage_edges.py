"""Persistence/credential checks independent of engine evaluation and graph features."""
from concurrent.futures import ThreadPoolExecutor
import pytest
from peaso.auth import CredentialCipher
from peaso.storage import SQLiteStore, StoreError


def test_concurrent_credential_key_initialization_uses_one_durable_key(tmp_path):
    identity = tmp_path / "identity"
    with ThreadPoolExecutor(max_workers=12) as executor:
        ciphers = list(executor.map(lambda _: CredentialCipher(identity), range(24)))
    ciphertext = ciphers[0].encrypt({"token": "inert-secret-key-concurrency-marker"})
    assert all(cipher.decrypt(ciphertext) == {"token": "inert-secret-key-concurrency-marker"} for cipher in ciphers)
    assert (identity / "credentials.key").stat().st_mode & 0o777 == 0o600
    assert list(identity.glob("*.tmp")) == []


def test_concurrent_conflicting_idempotency_requests_do_not_double_charge(tmp_path):
    store = SQLiteStore(tmp_path)
    connector = store.add_connector("tenant", {"provider": "aws"}, "ciphertext")
    def reserve(index):
        try:
            return store.enqueue("tenant", {"connector_id": connector["id"], "categories": ["hardening" if index % 2 else "network"]}, limit=10, idem="same-key")
        except StoreError as exc:
            return exc.status
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(reserve, range(20)))
    assert sum(result == 409 for result in results) == 10
    assert len({result["id"] for result in results if isinstance(result, dict)}) == 1
    assert store.usage("tenant") == 1


def test_enqueued_request_is_immutable_after_connector_change_and_deletion(tmp_path):
    store = SQLiteStore(tmp_path)
    connector = store.add_connector("tenant", {"provider": "aws", "name": "original"}, "original-ciphertext")
    request = {"connector_id": connector["id"]}
    job = store.enqueue("tenant", request, idem="immutable-key")
    captured = store.job("tenant", job["id"])["connector"]
    store.update_connector("tenant", connector["id"], {"name": "changed"}, "changed-ciphertext")
    store.delete_connector("tenant", connector["id"])
    assert store.job("tenant", job["id"])["connector"] == captured
    assert store.enqueue("tenant", request, idem="immutable-key")["id"] == job["id"]
    assert store.usage("tenant") == 1


def test_failed_transaction_rolls_back_quota_reservation(tmp_path):
    store = SQLiteStore(tmp_path)
    connector = store.add_connector("tenant", {"provider": "aws"}, "ciphertext")
    with store.connect() as database:
        database.execute("CREATE TRIGGER inert_failure BEFORE INSERT ON jobs BEGIN SELECT RAISE(ABORT,'inert transaction fault'); END")
    with pytest.raises(Exception):
        store.enqueue("tenant", {"connector_id": connector["id"]})
    assert store.usage("tenant") == 0 and store.jobs("tenant") == []


def test_expired_lease_cannot_be_renewed_or_publish_without_new_claim(tmp_path):
    store = SQLiteStore(tmp_path)
    connector = store.add_connector("tenant", {"provider": "aws"}, "ciphertext")
    job = store.enqueue("tenant", {"connector_id": connector["id"]}, timeout=100, now=1000)
    claim = store.claim("collector", lease_seconds=2, now=1001)
    assert not store.heartbeat(job["id"], claim["owner"], now=1004)
    assert not store.finish(job["id"], claim["owner"], "collected", "uncommitted-reference", now=1004)
    new_claim = store.claim("collector", now=1004)
    assert new_claim["owner"] != claim["owner"]
