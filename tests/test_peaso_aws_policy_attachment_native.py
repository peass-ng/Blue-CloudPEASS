"""Native IAM policy attachment joins must retain evidence gaps."""

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = "123456789012"
SCOPE = ACCOUNT + "/global"
POLICY_ARN = "arn:aws:iam::" + ACCOUNT + ":policy/Example"
CHECK = "aws.pci.iam.policy_attached_to_active_principal"


def _policy(attachment_count=0):
    return {"Arn": POLICY_ARN, "AttachmentCount": attachment_count,
            "_provenance": {"operation": "iam:GetAccountAuthorizationDetails", "native_response_complete": True},
            "PolicyVersionList": [{"IsDefaultVersion": True,
                "Document": {"Statement": [{"Effect": "Allow",
                    "Action": "s3:GetObject", "Resource": "*"}]}}]}


def _collection(kind, items, status=None, account=ACCOUNT):
    return {"type": kind, "scope": account + "/global", "service": "iam",
            "status": status or ("collected" if items else "empty"),
            "global": True, "account_id": account, "items": items}


def _result(policy=None, users=(), groups=(), roles=(), overrides=None,
            capture_at="2026-10-18T00:00:00+00:00"):
    collections = [_collection("iam_policy", [policy or _policy()]),
                   _collection("iam_user", list(users)),
                   _collection("iam_group", list(groups)),
                   _collection("iam_role", list(roles))]
    if overrides:
        collections = [overrides.get(row["type"], row) for row in collections]
    snapshot = make_snapshot("aws", [ACCOUNT + "/us-east-1"], collections,
                             created_at=capture_at)
    rows = [row for row in evaluate_snapshot(snapshot, checks=[CHECK])["findings"]
            if row["check_id"] == CHECK and not row["resource_id"].startswith("inventory:")]
    assert len(rows) == 1
    return rows[0]


def test_complete_native_empty_attachments_are_conclusive_failure():
    row = _result()
    assert row["status"] == "FAIL"


def _user(*, attached=True, activity=False):
    row = {"Arn": "arn:aws:iam::" + ACCOUNT + ":user/Alice", "UserName": "Alice",
           "_provenance": {"operation": "iam:GetAccountAuthorizationDetails", "native_response_complete": True},
           "AttachedManagedPolicies": [{"PolicyArn": POLICY_ARN}] if attached else [],
           "ServicesLastAccessedStatus": {"collection_status": "not_collected",
               "operation": "iam:GetServiceLastAccessedDetails", "granularity": "SERVICE_LEVEL"}}
    if activity:
        row["ServicesLastAccessedStatus"]["collection_status"] = "collected"
        row["ServicesLastAccessed"] = [{"ServiceNamespace": "s3",
            "LastAuthenticated": "2026-10-01T00:00:00+00:00"}]
    return row


def test_complete_native_join_requires_observed_activity_for_pass():
    row = _result(policy=_policy(1), users=[_user(activity=True)])
    assert row["status"] == "PASS"
    assert row["evidence"]["activity_source"] == "iam:GetServiceLastAccessedDetails"
    row = _result(policy=_policy(1), users=[_user()])
    assert row["status"] == "UNKNOWN"
    assert row["evidence"]["reason"] == "native IAM attachment activity unavailable"


def test_native_missing_or_incomplete_attachment_evidence_stays_unknown():
    missing = _user()
    del missing["AttachedManagedPolicies"]
    assert _result(policy=_policy(1), users=[missing])["status"] == "UNKNOWN"
    partial = _collection("iam_user", [_user(activity=True)], status="partial")
    assert _result(policy=_policy(1), users=[_user(activity=True)],
                   overrides={"iam_user": partial})["status"] == "UNKNOWN"
    denied = _collection("iam_user", [], status="denied")
    assert _result(policy=_policy(1), overrides={"iam_user": denied})["status"] == "UNKNOWN"


def test_native_foreign_duplicate_and_count_conflicts_stay_unknown():
    assert _result(policy=_policy(2), users=[_user(activity=True)])["status"] == "UNKNOWN"
    foreign_scope = _collection("iam_user", [_user(activity=True)], account="999999999999")
    assert _result(policy=_policy(1), overrides={"iam_user": foreign_scope})["status"] == "UNKNOWN"
    foreign_policy = _user(activity=True)
    foreign_policy["AttachedManagedPolicies"] = [{"PolicyArn": "arn:aws:iam::999999999999:policy/Other"}]
    assert _result(policy=_policy(1), users=[foreign_policy])["status"] == "UNKNOWN"
    duplicate = _user(activity=True)
    assert _result(policy=_policy(2), users=[duplicate, duplicate])["status"] == "UNKNOWN"
    duplicated_attachment = _user(activity=True)
    duplicated_attachment["AttachedManagedPolicies"].append({"PolicyArn": POLICY_ARN})
    assert _result(policy=_policy(2), users=[duplicated_attachment])["status"] == "UNKNOWN"


def test_native_group_attachment_without_member_activity_stays_unknown():
    group = {"Arn": "arn:aws:iam::" + ACCOUNT + ":group/Ops", "GroupName": "Ops",
             "_provenance": {"operation": "iam:GetAccountAuthorizationDetails", "native_response_complete": True},
             "AttachedManagedPolicies": [{"PolicyArn": POLICY_ARN}],
             "Users": [{"UserName": "Alice"}]}
    assert _result(policy=_policy(1), users=[_user(attached=False, activity=True)],
                   groups=[group])["status"] == "UNKNOWN"


def test_native_role_last_used_is_activity_proof_but_trust_alone_is_not():
    role = {"Arn": "arn:aws:iam::" + ACCOUNT + ":role/Worker", "RoleName": "Worker",
            "_provenance": {"operation": "iam:GetAccountAuthorizationDetails", "native_response_complete": True},
            "AttachedManagedPolicies": [{"PolicyArn": POLICY_ARN}],
            "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow",
                "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}]}}
    assert _result(policy=_policy(1), roles=[role])["status"] == "UNKNOWN"
    role["RoleLastUsed"] = {"LastUsedDate": "2026-10-01T00:00:00+00:00"}
    row = _result(policy=_policy(1), roles=[role])
    assert row["status"] == "PASS"
    assert row["evidence"]["activity_source"] == "iam:GetAccountAuthorizationDetails.RoleLastUsed"
    role["RoleLastUsed"]["LastUsedDate"] = "not-a-date"
    assert _result(policy=_policy(1), roles=[role])["status"] == "UNKNOWN"


def test_future_or_before_creation_role_use_cannot_prove_active():
    role = {"Arn": "arn:aws:iam::" + ACCOUNT + ":role/Worker", "RoleName": "Worker",
            "CreateDate": "2026-10-01T00:00:00+00:00",
            "_provenance": {"operation": "iam:GetAccountAuthorizationDetails", "native_response_complete": True},
            "AttachedManagedPolicies": [{"PolicyArn": POLICY_ARN}],
            "RoleLastUsed": {"LastUsedDate": "2026-10-19T00:00:00+00:00"}}
    assert _result(policy=_policy(1), roles=[role])["status"] == "UNKNOWN"
    role["RoleLastUsed"]["LastUsedDate"] = "2026-09-30T00:00:00+00:00"
    assert _result(policy=_policy(1), roles=[role])["status"] == "UNKNOWN"


def test_service_activity_time_must_fit_capture_and_principal_lifetime():
    user = _user(activity=True)
    user["CreateDate"] = "2026-09-01T00:00:00+00:00"
    assert _result(policy=_policy(1), users=[user])["status"] == "PASS"
    user["ServicesLastAccessed"][0]["LastAuthenticated"] = "2026-10-19T00:00:00+00:00"
    assert _result(policy=_policy(1), users=[user])["status"] == "UNKNOWN"
    user["ServicesLastAccessed"][0]["LastAuthenticated"] = "2026-08-31T00:00:00+00:00"
    assert _result(policy=_policy(1), users=[user])["status"] == "UNKNOWN"
    user["ServicesLastAccessed"][0]["LastAuthenticated"] = "2026-10-01T00:00:00+00:00"
    user["CreateDate"] = "malformed"
    assert _result(policy=_policy(1), users=[user])["status"] == "UNKNOWN"
    del user["CreateDate"]
    assert _result(policy=_policy(1), users=[user], capture_at="malformed")["status"] == "UNKNOWN"
    assert _result(policy=_policy(1), users=[user], capture_at="2026-10-18T00:00:00")["status"] == "UNKNOWN"


def test_independent_valid_usage_can_resolve_other_invalid_usage_without_age_cutoff():
    invalid = _user(activity=True)
    invalid["Arn"] = "arn:aws:iam::" + ACCOUNT + ":user/Future"
    invalid["UserName"] = "Future"
    invalid["ServicesLastAccessed"][0]["LastAuthenticated"] = "2026-10-19T00:00:00+00:00"
    valid = _user(activity=True)
    valid["ServicesLastAccessed"][0]["LastAuthenticated"] = "2020-01-01T00:00:00+00:00"
    valid["CreateDate"] = "2019-12-31T00:00:00+00:00"
    row = _result(policy=_policy(2), users=[invalid, valid])
    assert row["status"] == "PASS"
    assert row["evidence"]["activity_source"] == "iam:GetServiceLastAccessedDetails"
