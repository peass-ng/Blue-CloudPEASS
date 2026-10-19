"""Deletion guard tests use fake metadata; never call real cloud mutation APIs."""
import json
import os

import pytest

from scripts.peaso_test_resources.session import AWS_ACCOUNT, AZ_SUBSCRIPTION, OperationError, Session, TASK


def session(tmp_path):
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps({"schema_version": 1, "task_id": TASK, "resources": []}))
    return Session(path)


def row(session, provider="aws", kind="bucket"):
    return {"provider": provider, "kind": kind, "name": "peaso-test-owned", "id": "peaso-test-owned", "owner_token": session.owner,
            "account": AWS_ACCOUNT, "subscription": AZ_SUBSCRIPTION, "creation_status": "created", "verification": "pending"}


def test_ledger_is_private_and_wrong_task_rejected(tmp_path):
    instance = session(tmp_path)
    assert os.stat(instance.path).st_mode & 0o777 == 0o600
    data = json.loads(instance.path.read_text())
    data["task_id"] = "foreign-task"
    instance.path.write_text(json.dumps(data))
    with pytest.raises(OperationError, match="ownership"):
        Session(instance.path)


@pytest.mark.parametrize("change", [{"owner_token": "foreign"}, {"name": "existing-resource"}, {"account": "111122223333"}])
def test_wrong_ownership_never_calls_cloud(tmp_path, monkeypatch, change):
    instance = session(tmp_path)
    resource = {**row(instance), **change}
    def forbidden(*args, **kwargs):
        raise AssertionError("Unowned resource reached cloud operation")
    monkeypatch.setattr(instance, "aws", forbidden)
    monkeypatch.setattr(instance, "write", forbidden)
    with pytest.raises(OperationError):
        instance.remove(resource)


def test_wrong_bucket_tag_never_deletes(tmp_path, monkeypatch):
    instance = session(tmp_path)
    def metadata(*args, **kwargs):
        if args[1] == "head-bucket":
            return {}
        if args[1] == "get-bucket-tagging":
            return {"TagSet": [{"Key": "peaso-test-owner", "Value": "someone-else"}]}
        raise AssertionError("Unexpected cloud read")
    monkeypatch.setattr(instance, "aws", metadata)
    monkeypatch.setattr(instance, "write", lambda *a, **k: pytest.fail("Unowned bucket deleted"))
    with pytest.raises(OperationError, match="tag mismatch"):
        instance.remove(row(instance))


def test_nonempty_bucket_refuses_unexpected_object_deletion(tmp_path, monkeypatch):
    instance = session(tmp_path)
    def metadata(*args, **kwargs):
        return {"TagSet": [{"Key": "peaso-test-owner", "Value": instance.owner}]} if args[1] == "get-bucket-tagging" else {"KeyCount": 1} if args[1] == "list-objects-v2" else {}
    monkeypatch.setattr(instance, "aws", metadata)
    monkeypatch.setattr(instance, "write", lambda *a, **k: pytest.fail("Nonempty bucket deleted"))
    with pytest.raises(OperationError, match="not empty"):
        instance.remove(row(instance))


def test_azure_group_refuses_recursive_deletion_of_unledgered_children(tmp_path, monkeypatch):
    instance = session(tmp_path)
    def metadata(*args, **kwargs):
        return {"tags": {"peaso-test-owner": instance.owner}} if args[:2] == ("group", "show") else [{"id": "foreign-child"}]
    monkeypatch.setattr(instance, "az", metadata)
    monkeypatch.setattr(instance, "write", lambda *a, **k: pytest.fail("Unledgered child recursively deleted"))
    with pytest.raises(OperationError, match="Unledgered"):
        instance.remove(row(instance, "azure", "resource_group"))


def test_absence_verification_makes_cleanup_idempotent(tmp_path, monkeypatch):
    instance = session(tmp_path)
    instance.data["resources"] = [row(instance)]
    calls = []
    monkeypatch.setattr(instance, "aws", lambda *args, **kwargs: calls.append(args) or None)
    monkeypatch.setattr(instance, "write", lambda *a, **k: pytest.fail("Already absent resource mutated"))
    instance.cleanup()
    first_calls = list(calls)
    instance.cleanup()
    assert calls == first_calls
    assert instance.data["resources"][0]["creation_status"] == "deleted"
    assert instance.data["resources"][0]["verification"] == "not_found"
