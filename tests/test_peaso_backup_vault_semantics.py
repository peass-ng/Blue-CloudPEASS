"""Vault key metadata, recovery-point encryption, and EFS subnet scope."""
from __future__ import annotations

import copy

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import claude2_aws_b  # noqa: F401 - native registration
from peaso.checks.fixtures import CASES


VAULT = "aws.c2b.backup.vault_encrypted"
POINT = "aws.c2b.backup.recovery_point_encrypted"
EFS_SUBNET = "aws.c2b.efs.mount_target_subnet_no_auto_public_ip"
EFS_ROUTE = "aws.c2b.efs.no_public_mount_targets"
ARN = "arn:aws:backup:us-east-1:111111111111:backup-vault:v1"
KEY = "arn:aws:kms:us-east-1:111111111111:key/k1"


def assess(cid, item, index=None):
    return evaluate_check(cid, copy.deepcopy(item), copy.deepcopy(index or {}))


def vault(**extra):
    return {"BackupVaultArn": ARN, "BackupVaultName": "v1", **extra}


def detail(key=KEY, arn=ARN, status="collected"):
    return {"collection_status": status, "BackupVaultArn": arn, **({"EncryptionKeyArn": key} if key is not None else {})}


def test_vault_key_observed_from_list_or_matching_describe_only():
    state, evidence = assess(VAULT, vault(EncryptionKeyArn=KEY))
    assert state == "PASS" and evidence["encryption_key_arn"] == KEY
    assert evidence["source_api"] == "backup:ListBackupVaults"
    state, evidence = assess(VAULT, vault(Configuration=detail()))
    assert state == "PASS" and evidence["source_api"] == "backup:DescribeBackupVault"
    assert "recovery point encryption is assessed separately" in evidence["criterion"]
    assert assess(VAULT, vault(EncryptionKeyArn=KEY, Configuration=detail()))[0] == "PASS"


def test_missing_denied_conflicting_and_malformed_vault_key_are_unknown():
    for row in (
        vault(),
        vault(EncryptionKeyArn=None),
        vault(EncryptionKeyArn=""),
        vault(EncryptionKeyArn="not-an-arn"),
        vault(EncryptionKeyArn=7),
        vault(Configuration=detail(key=None)),
        vault(Configuration=detail(status="denied")),
        vault(Configuration=detail(arn="arn:aws:backup:us-east-1:111111111111:backup-vault:other")),
        vault(EncryptionKeyArn=KEY, Configuration=detail(key=None)),
        vault(EncryptionKeyArn=KEY, Configuration=detail(key="arn:aws:kms:us-east-1:111111111111:key/other")),
    ):
        assert assess(VAULT, row)[0] == "UNKNOWN", row
    state, evidence = assess(VAULT, vault(Configuration=detail(status="denied")))
    assert state == "UNKNOWN" and evidence["detail_collection_status"] == "denied"
    state, evidence = assess(VAULT, vault(Configuration=detail(key=None)))
    assert state == "UNKNOWN" and "did not report" in evidence["reason"]


def test_recovery_point_boolean_evidence_is_unchanged():
    base = {"RecoveryPointArn": "arn:aws:backup:us-east-1:111111111111:recovery-point:rp1", "BackupVaultName": "v1"}
    assert assess(POINT, {**base, "IsEncrypted": True})[0] == "PASS"
    assert assess(POINT, {**base, "IsEncrypted": False})[0] == "FAIL"
    assert assess(POINT, base)[0] == "UNKNOWN"
    assert assess(POINT, {**base, "IsEncrypted": "false"})[0] == "UNKNOWN"


def test_efs_policy_is_subnet_auto_ip_not_claim_of_public_mount_target_ip():
    checks = {row.id: row for row in CHECKS}
    assert "subnet" in checks[EFS_SUBNET].title.lower()
    cases = CASES[EFS_SUBNET]
    for name, expected in (("pass", "PASS"), ("fail", "FAIL")):
        state, evidence = assess(EFS_SUBNET, cases[name], cases[name + "_index"])
        assert state == expected and isinstance(evidence["map_public_ip_on_launch"], bool)
    incomplete = copy.deepcopy(cases["pass_index"])
    subnet = incomplete["subnet"][0]["data"]
    subnet.pop("MapPublicIpOnLaunch", None)
    assert assess(EFS_SUBNET, cases["pass"], incomplete)[0] == "UNKNOWN"
    assert "internet gateway" in checks[EFS_ROUTE].title.lower() or "public subnet" in checks[EFS_ROUTE].title.lower()
