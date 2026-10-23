"""Dynamo transaction contract without a cloud table or moto dependency."""
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeDeserializer

from peaso.storage.dynamodb import DynamoStore
from peaso.storage.sqlite import StoreError


@pytest.mark.parametrize("checkpoint_only", [False, True])
def test_dynamo_resume_transaction_is_same_row_and_exactly_once(checkpoint_only):
    ident = "a" * 32
    connector = {"id": "b" * 32, "tenant": "owner", "rev": 2,
                 "data": json.dumps({"provider": "aws", "scopes": ["123456789012/us-east-1"],
                                     "input_mode": "live"}), "auth": "rotated-sealed-auth"}
    row = {"id": ident, "tenant": "owner", "connector_id": connector["id"],
           "connector": json.dumps({"data": json.loads(connector["data"]), "auth": "prior-sealed-auth"}),
           "status": "credentials_expired", "snapshot": None if checkpoint_only else "saved-snapshot",
           "partial_snapshot": "saved-partial" if checkpoint_only else None,
           "partial_report": "saved-report" if checkpoint_only else None,
           "partial_report_sequence": 2 if checkpoint_only else None,
           "checkpoint_sequence": 2,
           "created": 100.0, "deadline": 200.0, "resume_attempt": 0,
           "history": [{"status": "credentials_expired", "at": "prior"}],
           "data": json.dumps({"checks": ["original"]})}
    lock = threading.Lock()

    class FakeClient:
        def transact_write_items(self, *, TransactItems):
            if "Delete" in TransactItems[0]:
                raise ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "No old reservation"}}, "TransactWriteItems")
            check, update = TransactItems
            assert check["ConditionCheck"]["ConditionExpression"] == "#rev=:revision"
            operation = update["Update"]
            assert "REMOVE admitted_at" in operation["UpdateExpression"]
            assert "resume_attempt=:old_attempt" in operation["ConditionExpression"]
            values = {key: TypeDeserializer().deserialize(value) for key, value in
                      operation["ExpressionAttributeValues"].items()}
            with lock:
                if row["status"] != values[":old_status"] or row["resume_attempt"] != values[":old_attempt"]:
                    raise ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "CAS"}}, "TransactWriteItems")
                row.update(status="queued", connector=values[":connector"],
                           deadline=float(values[":deadline"]), resume_attempt=int(values[":attempt"]),
                           resume_phase=values[":phase"], owner=None, lease=None)
                row.pop("admitted_at", None)

    store = object.__new__(DynamoStore)
    store.table = "fake"
    store.client = FakeClient()
    store.clock = lambda: 150.0
    store.job = lambda tenant, scan: dict(row)
    store.connector = lambda tenant, scan: dict(connector)
    store.public_job = lambda value: dict(value)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(store.resume_job, "owner", ident, connector, 150.0) for _ in range(2)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except StoreError as exc:
                outcomes.append(exc.status)
    assert sum(isinstance(value, dict) for value in outcomes) == 1
    assert 409 in outcomes
    assert row["id"] == ident and row["created"] == 100.0
    assert row["data"] == json.dumps({"checks": ["original"]})
    assert row["snapshot"] == (None if checkpoint_only else "saved-snapshot")
    assert row["partial_snapshot"] == ("saved-partial" if checkpoint_only else None)
    assert row["checkpoint_sequence"] == 2
    assert row["resume_attempt"] == 1 and row["resume_phase"] == "collector"
