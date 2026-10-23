"""Exact target and service prerequisites for IAM service credentials."""

from tests.test_peaso_privesc_aws_followups import ACCOUNT, ALICE, allow, aws_snap, real, reached, user


BOB = f"arn:aws:iam::{ACCOUNT}:user/bob"
SSH = "aws-iam-uploadsshpublickey-other-user"
SERVICE = "aws-iam-createservicespecificcredential-other-user"


def _ssh_snapshot(*, writer=BOB, target_git=True, key_count=0):
    actor = user("alice", allow("iam:UploadSSHPublicKey", resource=writer))
    target = user("bob", *( [allow("codecommit:GitPull")] if target_git else []))
    target["SSHPublicKeys"] = {"collection_status": "collected", "items": [
        {"SSHPublicKeyId": f"APKA{i}"} for i in range(key_count)]}
    return aws_snap([actor, target])


def test_upload_ssh_key_requires_exact_target_codecommit_git_right_and_free_slot():
    assert BOB in reached(real(_ssh_snapshot(), SSH), ALICE, SSH)
    assert BOB not in reached(real(_ssh_snapshot(writer=ALICE), SSH), ALICE, SSH)
    assert BOB not in reached(real(_ssh_snapshot(target_git=False), SSH), ALICE, SSH)
    assert BOB not in reached(real(_ssh_snapshot(key_count=5), SSH), ALICE, SSH)


def _service_snapshot(*, action="iam:CreateServiceSpecificCredential", writer=BOB,
                      target_git=True, existing=False):
    actor = user("alice", allow(action, resource=writer))
    target = user("bob", *( [allow("codecommit:GitPull")] if target_git else []))
    target["ServiceSpecificCredentials"] = {"collection_status": "collected", "items": ([
        {"ServiceName": "codecommit.amazonaws.com", "Status": "Active", "ServiceSpecificCredentialId": "ACCA1"}
    ] if existing else [])}
    return aws_snap([actor, target])


def test_create_service_credential_requires_exact_target_and_service_permission():
    assert BOB in reached(real(_service_snapshot(), SERVICE), ALICE, SERVICE)
    assert BOB not in reached(real(_service_snapshot(writer=ALICE), SERVICE), ALICE, SERVICE)
    assert BOB not in reached(real(_service_snapshot(target_git=False), SERVICE), ALICE, SERVICE)
    assert BOB not in reached(real(_service_snapshot(action="iam:ResetServiceSpecificCredential"), SERVICE), ALICE, SERVICE)
    assert BOB in reached(real(_service_snapshot(action="iam:ResetServiceSpecificCredential", existing=True), SERVICE), ALICE, SERVICE)
