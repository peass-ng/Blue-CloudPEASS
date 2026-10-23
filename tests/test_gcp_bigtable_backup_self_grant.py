"""An exact usable Bigtable backup can receive a new restore grant."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
INSTANCE = PROJECT + "/instances/i1"
SOURCE_TABLE = INSTANCE + "/tables/private"
BACKUP = INSTANCE + "/clusters/c1/backups/b1"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-bigtable-backups-setiampolicy-backup-self-grant"


def snapshot(*, write=True, prior=False, ready=True, expiry="2099-01-01T00:00:00Z",
             backup_policy="collected", instance_policy="collected", encryption="GOOGLE_DEFAULT_ENCRYPTION"):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}
    writer = PROJECT + "/roles/backupPolicyWriter"
    restorer = PROJECT + "/roles/backupRestorer"
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [
                    {"name": writer, "includedPermissions":
                     ["bigtable.backups.setIamPolicy"] if write else []},
                    {"name": restorer, "includedPermissions": ["bigtable.backups.restore"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": [
                    {"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("bigtable_instance", [{"name": INSTANCE,
                    "iamPolicy": {"bindings": []},
                    "_coverage": {"iamPolicy": {"status": instance_policy}}}]),
                row("bigtable_backup", [{"name": BACKUP, "sourceTable": SOURCE_TABLE,
                    "state": "READY" if ready else "CREATING", "expireTime": expiry,
                    "encryptionInfo": {"encryptionType": encryption},
                    "iamPolicy": {"bindings": [
                        {"role": restorer, "members": [SOURCE]}] if prior else []},
                    "_coverage": {"iamPolicy": {"status": backup_policy}}}]),
            ]}


def targets(snap):
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {tid: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for tid, grant in reach.targets.items()
            if tid.startswith("gcp_verified_authority:possible-bigtable-backup-self-grant:")}


def test_ready_unexpired_backup_policy_write_adds_restore_permission():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-bigtable-backup-self-grant:" + BACKUP: "conditional"}


def test_no_write_or_existing_restore_is_not_a_gain():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(prior=True))


def test_expired_backup_is_not_restorable_and_incomplete_evidence_is_not_positive():
    assert not targets(snapshot(expiry="2020-01-01T00:00:00Z"))
    for kwargs in ({"ready": False}, {"backup_policy": "denied"},
                   {"instance_policy": "denied"},
                   {"encryption": "CUSTOMER_MANAGED_ENCRYPTION"}):
        assert "conditional" not in targets(snapshot(**kwargs)).values()
