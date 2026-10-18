import pytest

from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot, collection

CID = "gcp.sql.iam_database_authentication"


def observe(rows, *, paged=False):
    def resolve(request):
        if request["url"].endswith("/instances"):
            return {"items": [{"name": "db", "databaseVersion": "MYSQL_8_0"}]}
        assert request["url"].endswith("/db/users")
        if paged:
            second = bool(request["params"].get("pageToken"))
            return {"items": [rows[int(second)]], **({} if second else {"nextPageToken": "more"})}
        return {"items": rows}
    captured, transport = snapshot(["sql_instance"], resolve)
    findings = [row for row in evaluate_snapshot(captured, checks=[CID])["findings"]
                if row["check_id"] == CID]
    assert len(findings) == 1
    instance = collection(captured, "sql_instance")["items"][0]
    assert all(request["method"] == "GET" for request in transport.requests)
    return findings[0]["status"], instance["usersList"], transport


@pytest.mark.parametrize("paged,expected", [(False, "malformed"), (True, "partial")])
def test_duplicate_same_account_conflicting_auth_type_cannot_prove_iam_user(paged, expected):
    rows = [
        {"name": "same", "host": "%", "type": "CLOUD_IAM_USER"},
        {"name": "same", "host": "%", "project": "p-one", "instance": "db",
         "type": "BUILT_IN", "passwordPolicy": {"enableFailedAttemptsCheck": False}},
    ]
    status, users, transport = observe(rows, paged=paged)
    assert status == "UNKNOWN"
    assert users["status"] == expected
    assert users["error"]["code"] == "sql_user_duplicate_identity"
    assert len(transport.requests) == (3 if paged else 2)


def test_duplicate_same_account_conflicting_password_policy_is_incomplete():
    rows = [
        {"name": "same", "host": "%", "type": "BUILT_IN",
         "passwordPolicy": {"enableFailedAttemptsCheck": True, "allowedFailedAttempts": 3}},
        {"name": "same", "host": "%", "type": "BUILT_IN",
         "passwordPolicy": {"enableFailedAttemptsCheck": False, "allowedFailedAttempts": 0}},
    ]
    status, users, _ = observe(rows)
    assert status == "UNKNOWN"
    assert users["status"] == "malformed"
    assert users["error"]["code"] == "sql_user_duplicate_identity"


def test_same_username_distinct_hosts_remains_two_accounts():
    rows = [
        {"name": "same", "host": "%", "type": "CLOUD_IAM_USER"},
        {"name": "same", "host": "localhost", "project": "p-one", "instance": "db",
         "type": "BUILT_IN"},
    ]
    status, users, _ = observe(rows)
    assert status == "PASS"
    assert users["status"] == "collected"
    assert {(row["name"], row["host"]) for row in users["items"]} == {
        ("same", "%"), ("same", "localhost")}
