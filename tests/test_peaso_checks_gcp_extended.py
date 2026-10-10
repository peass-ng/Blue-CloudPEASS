"""Source-reviewed native GCP predicates: positive, negative and coverage gaps."""
import copy
import json
from pathlib import Path

import pytest

# Explicit module import until the registry owner's coordinated import lands.
from peaso.checks import gcp_extended, CHECKS
from peaso.checks.fixtures import CASES

CHECKS_BY_ID = {check.id: check for check in CHECKS if check.id in gcp_extended.IDS}


@pytest.mark.parametrize("cid", gcp_extended.IDS)
@pytest.mark.parametrize("case,status", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"),
                                         ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_all_reviewed_predicates_strict_and_immutable(cid, case, status):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    original = copy.deepcopy(item)
    result, evidence = CHECKS_BY_ID[cid].evaluate(item, {})
    assert result == status, (cid, case, evidence)
    assert isinstance(evidence, dict)
    assert item == original


@pytest.mark.parametrize("cid", gcp_extended.IDS)
def test_denied_detail_cannot_become_a_configuration_pass(cid):
    item = copy.deepcopy(CASES[cid]["pass"])
    field = next(key for key in item if not key.startswith("_"))
    item["_coverage"] = {field: {"status": "denied", "error": {"code": "permission_denied"}}}
    assert CHECKS_BY_ID[cid].evaluate(item, {})[0] == "UNKNOWN"


def evaluate(suffix, item):
    return CHECKS_BY_ID[gcp_extended.PREFIX + suffix].evaluate(item, {})


def test_gke_naming_exemptions_remain_owner_review():
    assert evaluate("compute.ip_forwarding", {"name": "gke-node", "canIpForward": True})[0] == "MANUAL"
    assert evaluate("compute.single_interface", {"name": "gke-node", "networkInterfaces": [{}, {}]})[0] == "MANUAL"
    assert evaluate("compute.no_default_service_account", {"name": "gke-node", "serviceAccounts":
        [{"email": "123-compute@developer.gserviceaccount.com"}]})[0] == "MANUAL"


def test_persistent_disk_rule_does_not_treat_ephemeral_scratch_as_backup_policy():
    assert evaluate("compute.disk_auto_delete", {"disks": [{"type": "SCRATCH", "autoDelete": True}]})[0] == "PASS"
    assert evaluate("compute.disk_auto_delete", {"disks": [{"type": "PERSISTENT", "autoDelete": "false"}]})[0] == "UNKNOWN"


def test_metadata_missing_duplicate_and_malformed_values_are_unknown():
    for rows in [[], [{"key": "serial-port-enable", "value": "unexpected"}],
                 [{"key": "serial-port-enable", "value": "false"}] * 2]:
        assert evaluate("compute.no_serial_console", {"metadata": {"items": rows}})[0] == "UNKNOWN"
    assert evaluate("compute.no_serial_console", {"metadata": {"items": [{"key": "serial-port-enable", "value": "TRUE"}]}})[0] == "FAIL"


def test_sql_engine_applicability_and_known_enum_values():
    assert evaluate("sql.mysql_local_infile", {"databaseVersion": "POSTGRES_16"})[0] == "NOT_APPLICABLE"
    assert evaluate("sql.mysql_local_infile", {"databaseVersion": "MYSQL_8_0", "settings": {"databaseFlags": []}})[0] == "UNKNOWN"
    for flag, value, suffix in [("log_statement", "all", "sql.postgres_log_statement"),
                                ("log_error_verbosity", "verbose", "sql.postgres_log_error_verbosity")]:
        item = {"databaseVersion": "POSTGRES_16", "settings": {"databaseFlags": [{"name": flag, "value": value}]}}
        assert evaluate(suffix, item)[0] == "FAIL"
    assert evaluate("sql.high_availability", {"instanceType": "READ_REPLICA_INSTANCE"})[0] == "NOT_APPLICABLE"


def test_kms_rotation_uses_snapshot_time_exact_boundaries_and_purpose():
    item = copy.deepcopy(CASES[gcp_extended.PREFIX + "kms.rotation_90_days"]["pass"])
    item["nextRotationTime"] = "2026-10-09T00:00:00Z"
    assert evaluate("kms.rotation_90_days", item)[0] == "FAIL"
    item["nextRotationTime"] = "2027-01-08T00:00:01Z"  # 90 days plus one second
    assert evaluate("kms.rotation_90_days", item)[0] == "FAIL"
    item["nextRotationTime"] = "2027-01-08T00:00:00Z"
    assert evaluate("kms.rotation_90_days", item)[0] == "PASS"
    item["rotationPeriod"] = "7776000.000000001s"
    assert evaluate("kms.rotation_90_days", item)[0] == "FAIL"
    assert evaluate("kms.rotation_enabled", {"purpose": "ASYMMETRIC_SIGN"})[0] == "NOT_APPLICABLE"
    assert evaluate("kms.rotation_enabled", {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "bad"})[0] == "UNKNOWN"


def test_conditional_public_kms_binding_is_declared_member_evidence_only():
    item = {"iamPolicy": {"bindings": [{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": ["allUsers"],
        "condition": {"expression": "false"}}]}}
    status, evidence = evaluate("kms.no_public_iam", item)
    assert status == "FAIL"
    assert evidence["public_bindings"][0]["condition"] == {"expression": "false"}
    assert "no effective-access claim" in evidence["semantics"]


def test_reviewed_shard_claims_only_exact_supported_upstream_predicates():
    pack = Path(__file__).resolve().parents[1] / "peaso" / "rulepacks"
    reviewed = json.loads((pack / "reviewed_gcp.json").read_text())
    source_rows = {row["check_id"]: row for row in json.loads((pack / "upstream_manifest.json").read_text())["checks"]}
    assert len(gcp_extended.IDS) >= 20
    assert sum(row["disposition"] == "ported" for row in reviewed.values()) >= 20
    associated = set()
    for upstream, row in reviewed.items():
        assert upstream in source_rows
        assert row["reason"] and row["official_docs"] and row["review_notes"]
        assert all(url.startswith("https://docs.cloud.google.com/") for url in row["official_docs"])
        ids = row["native_checks"] if row["disposition"] == "ported" else row["related_native_checks"]
        assert ids and set(ids) <= set(gcp_extended.IDS)
        if row["disposition"] == "pending":
            assert row["native_checks"] == []
        associated.update(ids)
    assert associated == set(gcp_extended.IDS)
