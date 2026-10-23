"""Exact graph cases for four broad AWS escalation routes."""

from peaso import privesc
from tests.test_peaso_privesc_schema_v2 import aws_snap as policy_version_snapshot

from test_peaso_privesc_audit_fixes import (
    ACCOUNT, ALICE, EC2_ROLE, REGION, _instances, aws, policy, reached, real, role, user,
)


ADMIN = f"aws_account_admin:{ACCOUNT}"
TRUSTED = "aws-sts-assumerole-trusted"
REWRITE = "aws-iam-updateassumerolepolicy"
POLICY_VERSION = "aws-iam-createpolicyversion-assumable-role"
SESSION = "aws-ssm-startsession"
TARGET = f"arn:aws:iam::{ACCOUNT}:role/target"
OTHER = f"arn:aws:iam::{ACCOUNT}:role/other"
INSTANCE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-1"
SHELL = f"arn:aws:ssm:{REGION}:{ACCOUNT}:document/SSM-SessionManagerRunShell"
PORT_FORWARD = f"arn:aws:ssm:{REGION}:{ACCOUNT}:document/AWS-StartPortForwardingSession"
CHANNEL = f"arn:aws:ssm:{REGION}:{ACCOUNT}:session/*"


def _trust(role_row, principal):
    role_row["AssumeRolePolicyDocument"] = policy({
        "Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"})
    return role_row


def test_trusted_assume_role_requires_exact_trust_and_assume_permission():
    target = _trust(role("target", profile=False), ALICE)
    actor = user("alice", {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": TARGET})
    assert reached(real(aws([actor], [target]), TRUSTED), ALICE, TRUSTED) == {TARGET: "derived"}

    wrong_trust = _trust(role("target", profile=False), f"arn:aws:iam::{ACCOUNT}:user/bob")
    assert TARGET not in reached(real(aws([actor], [wrong_trust]), TRUSTED), ALICE, TRUSTED)

    account_root = _trust(role("target", profile=False), f"arn:aws:iam::{ACCOUNT}:root")
    no_identity_grant = user("alice")
    assert TARGET not in reached(real(aws([no_identity_grant], [account_root]), TRUSTED), ALICE, TRUSTED)


def test_trust_rewrite_binds_exact_writable_role_and_excludes_service_linked_role():
    actor = user("alice", {"Effect": "Allow", "Action": "iam:UpdateAssumeRolePolicy", "Resource": TARGET})
    target = role("target", profile=False)
    assert reached(real(aws([actor], [target]), REWRITE), ALICE, REWRITE) == {TARGET: "derived"}

    wrong = user("alice", {"Effect": "Allow", "Action": "iam:UpdateAssumeRolePolicy", "Resource": OTHER})
    assert TARGET not in reached(real(aws([wrong], [target]), REWRITE), ALICE, REWRITE)

    service_linked = role("AWSServiceRoleForExample", path="/aws-service-role/example.amazonaws.com/", profile=False)
    linked_arn = service_linked["Arn"]
    linked_actor = user("alice", {"Effect": "Allow", "Action": "iam:UpdateAssumeRolePolicy", "Resource": linked_arn})
    assert linked_arn not in reached(real(aws([linked_actor], [service_linked]), REWRITE), ALICE, REWRITE)


def test_assumable_role_policy_version_needs_attached_editable_policy_and_capacity():
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == POLICY_VERSION)

    def graph(**changes):
        snapshot = policy_version_snapshot(**changes)
        return reached(privesc.analyze(snapshot, entries=[entry]), ALICE, POLICY_VERSION)

    assert graph().get(ADMIN) == "conditional"
    for changes in ({"edit": False}, {"trust": False}, {"versions": 5}, {"boundary": True}):
        assert ADMIN not in graph(**changes), changes
    assert graph(versions=5, delete=True).get(ADMIN) == "conditional"


def _session_snapshot(*, document=SHELL, channel=CHANNEL, state="running", ping="Online"):
    actions = [{"Effect": "Allow", "Action": "ssm:StartSession", "Resource": [INSTANCE, document]}]
    if channel:
        actions.append({"Effect": "Allow", "Action": "ssmmessages:OpenDataChannel", "Resource": channel})
    return aws([user("alice", *actions)], [role("ec2-role")], _instances(state=state, ping=ping))


def test_ssm_session_needs_online_instance_shell_document_and_future_data_channel():
    assert reached(real(_session_snapshot(), SESSION), ALICE, SESSION) == {EC2_ROLE: "conditional"}
    for changes in ({"document": PORT_FORWARD}, {"channel": None},
                    {"channel": f"arn:aws:ssm:{REGION}:{ACCOUNT}:session/old-session"},
                    {"state": "stopped"}, {"ping": "ConnectionLost"}):
        assert EC2_ROLE not in reached(real(_session_snapshot(**changes), SESSION), ALICE, SESSION), changes
