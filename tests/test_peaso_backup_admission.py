"""Public source-grounded AWS Backup frequency and retention admission fixture."""
from __future__ import annotations
from tests.release_successor_history import historical_release as read_historical_release

import copy
import hashlib
import json
import math
from pathlib import Path

import pytest

import peaso
import peaso.checks as checks_pkg
from peaso.checks import CHECKS, aws_backup_plan_frequency as backup
from peaso.checks.catalog import framework_ids_for, names_for_ids, requirement_tags_for
from peaso.checks.fixtures import CASES
from peaso.collectors import aws_policy
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot, validate

from tests.release_successor_history import (ancestor_json, ancestor_bytes, ancestor_sha, registered_before_bulk, registry_source_before_bulk)

CHECKS = registered_before_bulk(CHECKS)

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/compliance-ledgers"
PACK = ROOT / "peaso/rulepacks"
CID = backup.CHECK_ID
FREQ, PCI = "aws_backup_plan_rule_required_frequency", "aws.pci.backup.plan_frequency_retention"
KEYS = ("id", "provider", "resource_kind", "data_source", "predicate", "severity", "category", "title", "description", "remediation_hint")
ACCOUNT, REGION = "123456789012", "eu-west-1"
SCOPE = ACCOUNT + "/" + REGION
PLAN_ID = "22222222-2222-2222-2222-222222222222"
ARN = f"arn:aws:backup:{REGION}:{ACCOUNT}:plan:{PLAN_ID}"
DAILY = "cron(0 5 ? * * *)"
STEAMPIPE_FRAMEWORKS = sorted("aws-compliance.benchmark." + name for name in (
    "acsc_essential_eight", "cisa_cyber_essentials", "fedramp_low_rev_4", "fedramp_moderate_rev_4", "ffiec",
    "gxp_21_cfr_part_11", "gxp_eu_annex_11", "hipaa_final_omnibus_security_rule_2013", "hipaa_security_rule_2003",
    "nist_800_171_rev_2", "nist_csf", "nist_csf_v2", "nydfs_23", "pci_dss_v321", "pci_dss_v40", "rbi_itf_nbfc", "soc_2"))



def sha(data):
    return hashlib.sha256(data).hexdigest()


def spec_digest(spec):
    return sha(json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def check():
    matches = [item for item in CHECKS if item.id == CID]
    assert len(matches) == 1
    return matches[0]


def rule(schedule=DAILY, days=35, **extra):
    out = {"RuleName": "r", "TargetBackupVaultName": "vault", **extra}
    if schedule is not None:
        out["ScheduleExpression"] = schedule
    if days is not None:
        out["Lifecycle"] = {"DeleteAfterDays": days}
    return out


def plan(*rules, arn=ARN, **detail):
    return {"BackupPlanId": PLAN_ID, "BackupPlanArn": arn, "BackupPlanName": "p",
            "Plan": {"collection_status": "collected", "BackupPlanId": PLAN_ID, "BackupPlanArn": arn,
                     "BackupPlan": {"BackupPlanName": "p", "Rules": list(rules)}, **detail}}


def policy(hours=24, applies=(SCOPE,), **override):
    return {"status": "collected", "source": "operator-supplied", "basis": aws_policy.BASIS, "applies_to": list(applies),
            "required_frequency_hours": hours, "unmatched_scopes": [], **override}


def index(item, body="default", *, callers=None, status="collected", scope=SCOPE):
    metadata = {"caller_identities": callers if callers is not None else
                [{"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Audit/peaso-read-only"}]}
    if body == "default":
        body = policy()
    if body is not None:
        metadata["compliance_policy"] = {"aws_backup_plan": body}
    return {"context": {"provider": "aws", "scope": scope, "Account": scope.split("/")[0], "metadata": metadata},
            "collections": {"backup_plan": [{"type": "backup_plan", "scope": scope, "status": status,
                                             "items": [] if status != "collected" else [item]}]},
            "backup_plan": [{"type": "backup_plan", "scope": scope, "data": item}]}


def status(item, idx=None):
    return check().evaluate(item, index(item) if idx is None else idx)


# ------------------------------------------------------------------ registration and imports

def test_imports_resolve_to_current_source():
    for module in (peaso, checks_pkg, backup, aws_policy):
        assert ROOT.resolve() in Path(module.__file__).resolve().parents


def test_registration_metadata_uses_known_enum_and_no_bypass():
    item = check()
    assert (item.provider, item.category, item.kind, item.severity, item.control, item.target, item.dependencies) == (
        "aws", "hardening", "backup_plan", "medium", "CP-9", "resource", ["backup_plan"])
    assert item.title == "Backup plan min frequency and min retention check"
    assert item.evaluate.__wrapped__ is backup.backup_plan_frequency_retention_35


def test_registry_is_unique_and_held_proposals_stay_unregistered():
    ids = [item.id for item in CHECKS]
    assert len(ids) == len(set(ids)) == 3434
    assert FREQ in ids and PCI not in ids
    assert "peaso.checks.compliance_new_sw42" not in __import__("sys").modules
    assert "compliance_new_sw42" not in (ROOT / "peaso/checks/__init__.py").read_text()
    lines = registry_source_before_bulk().splitlines()
    assert len(lines) == 796
    lines = lines[:-9]  # PSC and the exact fourteen-check additive cohort.
    lines = lines[:-4]  # Preserve the exact prior grouped registry prefix.
    assert len(lines) == 783
    lines = lines[:-9]  # Preserve the historical 774-line registry proof.
    assert len(lines) == 774
    assert lines[-4].startswith("from . import next20_aws")
    lines = lines[:-5]
    assert len(lines) == 769
    assert lines[-6].startswith("from . import post_dfaf_aws, post_dfaf_azure")
    lines = lines[:-6]
    assert len(lines) == 763
    assert lines[-13].startswith("from . import aws_config_recording  ")
    assert lines[-12].startswith("from . import aws_backup_plan_frequency  ")
    assert lines[-11].startswith("from . import k8s_namespace_policy_presence  ")
    assert lines[-10].startswith("from . import compliance_new_k8s_component  ")
    assert lines[-9].startswith("from . import gcp_data_access  ")
    assert lines[-8].startswith("from . import wafv2_basic  ")
    assert lines[-7].startswith("from . import compliance_next_k8s  ")
    assert lines[-6].startswith("from . import batch_remaining_aws, batch_remaining_azure, ")
    assert lines[-5].startswith("from .fixtures import restore_remaining_batch_cases as ")
    assert lines[-4] == "_restore_remaining_batch_cases()"
    assert lines[-3] == "del _restore_remaining_batch_cases"
    assert lines[-2].startswith("alias_check('aws_g6_redshift_automatic_version_upgrade', ")
    assert lines[-1].startswith("alias_check('aws.pci.cloudtrail.authentication_events', ")


def test_generic_behavior_fixture_contract():
    item, cases = check(), CASES[CID]
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"), ("unknown", "UNKNOWN")):
        data, scoped = copy.deepcopy(cases[name]), copy.deepcopy(cases[name + "_index"])
        before, before_index = copy.deepcopy(data), copy.deepcopy(scoped)
        assert item.evaluate(data, scoped)[0] == expected
        assert data == before and scoped == before_index
    for value in ({}, None, {"collection_status": "denied"}):
        assert item.evaluate(value, cases["index"])[0] == "UNKNOWN"
    assert item.evaluate(cases["pass"], cases["index"])[0] == "UNKNOWN"  # fixture index has no operator policy


@pytest.mark.parametrize("collection_status,expected", [("denied", "DENIED"), ("unknown", "UNKNOWN"), ("malformed", "UNKNOWN"), ("empty", "EMPTY")])
def test_unavailable_inventory_never_passes(collection_status, expected):
    snapshot = make_snapshot("aws", ["test-scope"], [{"type": "backup_plan", "scope": "test-scope", "service": "test",
                                                     "status": collection_status, "items": []}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CID])
    assert report["findings"][0]["status"] == expected and "PASS" not in report["stats"]["by_status"]


# ------------------------------------------------------------------ signed spec, supersession and provenance

def catalogue():
    return {entry["id"]: entry for entry in json.loads((LEDGER / "new-checks-aws.json").read_text())}


def test_canonical_catalogue_carries_the_admitted_spec():
    entry = catalogue()[CID]
    assert spec_digest({key: entry[key] for key in KEYS}) == backup.PROPOSED_SPEC_SHA256
    assert entry["category"] == "hardening" and "operator" in entry["data_source"] and "at least one rule" in entry["predicate"]
    assert len(entry["requirements"]) == 17 and {r["framework_id"] for r in entry["requirements"]} == set(STEAMPIPE_FRAMEWORKS)


def test_superseded_canonical_bytes_are_preserved():
    companion = json.loads((LEDGER / "provenance/aws_nist_backup_plan_min_retention_35_days.superseded-4ce264ac.json").read_text())
    original = {key: companion["superseded_catalogue_entry"][key] for key in KEYS}
    assert spec_digest(original) == companion["superseded_spec_sha256"] == backup.SUPERSEDED_SPEC_SHA256
    assert sha(companion["superseded_spec_canonical_json"].encode()) == backup.SUPERSEDED_SPEC_SHA256
    assert companion["superseded_by_spec_sha256"] == backup.PROPOSED_SPEC_SHA256
    assert companion["changed_fields"] == ["data_source", "predicate", "category", "description", "remediation_hint"]
    assert companion["superseded_catalogue_entry"]["category"] == "compliance"
    # The supersession records the manifest at proposal time, not the later combined manifest.
    assert companion["proposed_in"]["proposed_ledger_manifest_sha256"] == "c1d5fececc46eebe0dace780a679bb3dcdbe3fd3a70686ad294d632d80148dc0"
    assert companion["proposed_in"]["evaluator_sha256"] == sha((ROOT / "peaso/checks/aws_backup_plan_frequency.py").read_bytes())
    assert len(companion["association_changes"]) == 17
    current = catalogue()[CID]
    assert all(current[key] == original[key] for key in KEYS if key not in companion["changed_fields"])
    assert "provenance/aws_nist_backup_plan_min_retention_35_days.superseded-4ce264ac.json" in \
        (ROOT / "scripts/peaso_compliance_compile.py").read_text()


def test_held_proposals_keep_their_exact_specs():
    entries = catalogue()
    assert spec_digest({key: entries[FREQ][key] for key in KEYS}) == "a066b3c973571b3d1df8aa9871dba4858a8c9c4c707897639d99e116ec71d1ea"
    assert spec_digest({key: entries[PCI][key] for key in KEYS}) == "2aee0ca0af6fdff32bac983fba5b8b49e01b43acf2d8eb01180e3ba37bd1f81d"
    assert sorted((r["framework_id"], r["requirement_id"]) for r in entries[FREQ]["requirements"]) == [
        ("nist_800_53_revision_5_aws", "cp_9_a"), ("nist_800_53_revision_5_aws", "cp_9_b")]
    assert len(entries[PCI]["requirements"]) == 10
    assert {r["framework_id"] for r in entries[PCI]["requirements"]} == {
        "pci_4.0_aws", "fedramp_low_revision_4_aws", "fedramp_moderate_revision_4_aws", "nist_800_53_revision_4_aws"}


def ledger_rows():
    for path in sorted(LEDGER.glob("aws-*.json")):
        for framework in json.loads(path.read_text())["frameworks"]:
            for row in framework["requirements"]:
                yield path.name, framework["id"], row


def test_signed_rows_embed_one_spec_and_no_duplicate_association():
    specs, rows = set(), []
    for _, framework_id, row in ledger_rows():
        for spec in row["new_checks"]:
            if spec["id"] == CID:
                specs.add(json.dumps(spec, sort_keys=True))
                rows.append((framework_id, row["requirement_id"]))
                assert row["decision"] == "PARTIAL" and row["native_checks"] == ["aws.c2b.backup.plan_rules_retention_35"]
                assert [s["id"] for s in row["new_checks"]] == [CID] and CID not in row["removed_checks"]
    assert len(specs) == 1 and spec_digest(json.loads(specs.pop())) == backup.PROPOSED_SPEC_SHA256
    assert sorted(rows) == sorted((fid, "aws-compliance.control.backup_plan_min_retention_35_days") for fid in STEAMPIPE_FRAMEWORKS)


def test_manifest_and_supplement_bind_the_admitted_spec():
    manifest = ancestor_json(LEDGER / "manifest.json")
    for section in ("slices", "descriptions"):
        for row in manifest[section].values():
            assert row["sha256"] == sha((LEDGER / row["path"]).read_bytes())
    assert manifest["new_descriptions"]["checks"] == 329
    assert manifest["new_descriptions"]["sha256"] == sha(ancestor_bytes(LEDGER / manifest["new_descriptions"]["path"]))
    supplement = ancestor_json(LEDGER / "descriptions/implemented-new-checks.json")
    assert supplement[CID]["proposed_spec_sha256"] == backup.PROPOSED_SPEC_SHA256 and len(supplement) == 329


# ------------------------------------------------------------------ framework links and compiled packs

def test_framework_links_are_exactly_the_same_control_rows_plus_hacktricks():
    assert framework_ids_for(CID) == STEAMPIPE_FRAMEWORKS
    tags = requirement_tags_for(CID)
    assert len(tags) == 17 and {t["runtime_status"] for t in tags} == {"partial"} and {t["decision"] for t in tags} == {"PARTIAL"}
    assert {t["requirement_id"] for t in tags} == {"aws-compliance.control.backup_plan_min_retention_35_days"}
    frameworks = check().frameworks
    assert frameworks == names_for_ids(STEAMPIPE_FRAMEWORKS) and frameworks[0] == "HackTricks Cloud Best Practices"


def test_compiled_pack_conserves_status_counts_and_keeps_held_rows_pending():
    requirements = ancestor_json(PACK / "compliance_requirements.json")
    assert requirements["source_manifest_sha256"] == sha(ancestor_bytes(LEDGER / "manifest.json"))
    assert requirements["counts"] == {"automated": 9566, "manual": 5957, "not_applicable": 651, "not_assessed": 1387, "partial": 4651}
    rows = {(fw["id"], row["requirement_id"]): row for fw in requirements["frameworks"] for row in fw["requirements"]}
    for key in (("nist_800_53_revision_5_aws", "cp_9_a"), ("nist_800_53_revision_5_aws", "cp_9_b")):
        assert FREQ in rows[key]["native_checks"] and rows[key]["pending_checks"] == []
        assert rows[key]["runtime_status"] == "partial"
    for rid in ("10.3.3.2", "10.5.1.1", "3.2.1.1", "3.3.1.1.1", "3.3.1.3.1", "3.3.2.1", "3.3.3.1"):
        assert rows[("pci_4.0_aws", rid)]["pending_checks"] == [PCI] and rows[("pci_4.0_aws", rid)]["runtime_status"] == "not_assessed"
    assert {spec["id"] for spec in requirements["proposed_checks"]} >= {CID, FREQ, PCI}


def test_compiled_packs_match_pinned_admission_bytes():
    # The accepted Source649 package retains the pre-APIM 3,408-check packs.
    historical_release = read_historical_release(ROOT / 'infra/aws/build/peaso-source-649803fb5d475bee5dfcfc33ab91dbef803ba117b5d9949f08e273debae5b646.zip')
    assert read_historical_release(ROOT / 'infra/aws/build/peaso-source-bb12ea10f8c3b32e7902108232bb92c982cffbfddfe6130ab94d9cbf8bc202f9.zip')['source_version']=='bb12ea10f8c3b32e7902108232bb92c982cffbfddfe6130ab94d9cbf8bc202f9'
    assert historical_release["source_version"] == "649803fb5d475bee5dfcfc33ab91dbef803ba117b5d9949f08e273debae5b646"
    assert len(historical_release["files"]) == 1554
    assert historical_release["files"]["peaso/rulepacks/native_catalog.json"] == "fc7606530fb6df4f99874f3629e38e2618a82fb2d1804540947aad88c6a15001"
    expected = {
        "catalog_summary.json": 'b90f7860fb08b076e933c8469993888255dbb4963a5540422fd82067d4912439',
        "check_descriptions.json": 'b45c3a13ea0fe6ef085f52fd03078561cbebe477ba398d941f255d74315d80a2',
        "compliance_lookup.json": 'a8406177d03a050ed0f057e39d050a871a3823a519357751829a4423f56bab62',
        "compliance_requirements.json": '7eacec75a219e90a59578613f30ebe367f4b7d97b47b6dee3a5883dc35545a26',
        "framework_catalog.json": 'b991f8f65b92298da941b4761188e8a6c66bc4d9b2afd43553aa6ce6a6dd6e4a',
        "frontend/src/frameworkCatalog.json": "a4f89b9c3321d2c7c99b702677c00eabf848fe4c1696e604d27a2882a61ecb89",
        "native_catalog.json": 'c383dad30bc5da4429bddd25103487dc17593df70eee548f586e81cbb7c2380b',
        "runtime_metadata.json": 'da3623f3e9c2f3e39fb5375ba7835be29fdfa00d750f28beab2f699b7c3e53ed'
    }
    cohort = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/two_hour_native_cohort.json").read_text())
    for name in expected:
        key = name if "/" in name else "peaso/rulepacks/" + name
        if key in cohort["source_changes"]:
            expected[name] = cohort["source_changes"][key]["sha256"]
    for name, digest in expected.items():
        path = ROOT / name if "/" in name else PACK / name
        assert sha(ancestor_bytes(path)) == digest, name


# ------------------------------------------------------------------ evaluator semantics (at least one rule)

@pytest.mark.parametrize("rules,hours,expected", [
    ((rule(days=7), rule(days=None)), 24, "PASS"),                      # never-expiring daily rule qualifies
    ((rule(days=34), rule(days=35)), 24, "PASS"),                       # 35 days is the inclusive minimum
    ((rule("cron(0 5 ? * MON *)", 365), rule(DAILY, 35)), 24, "PASS"),  # one qualifying rule is enough
    ((rule(DAILY, 35),), 24, "PASS"),                                   # gap equal to the requirement qualifies
    ((rule("cron(0/30 * ? * * *)", 35),), 0.5, "PASS"),                 # fractional operator interval
    ((rule(DAILY, 35, ScheduleExpressionTimezone="Etc/GMT-14"),), 24, "PASS"),  # fixed-offset zone
    ((rule(DAILY, 35), rule("rate(1 day)", 35)), 24, "PASS"),           # proven qualifier outweighs an unresolved rule
    ((rule(DAILY, 34),), 24, "FAIL"),                                   # retention miss
    ((rule("cron(0 5 ? * MON *)", 35),), 24, "FAIL"),                   # frequency miss
    ((rule(DAILY, 34), rule("cron(0 5 ? * MON *)", 90)), 24, "FAIL"),   # every rule misses something
    ((rule(DAILY, 35),), 23.9, "FAIL"),
    ((rule("cron(0 5 29 2 ? *)", 35),), 744, "FAIL"),                   # leap-day cron: 2921-day exact gap
    ((rule("cron(0 5 31 * ? *)", 35),), 744, "FAIL"),                   # 31st: 61-day exact gap
    ((rule("cron(0 5 1 * ? *)", 35),), 744, "PASS"),                    # monthly 1st: 31-day gap fits 744 hours
    ((), 24, "FAIL"),                                                   # no rule can satisfy the requirement
    ((rule("rate(1 day)", 35),), 24, "UNKNOWN"),                        # rate() is not a documented Backup form
    ((rule(DAILY, 35, ScheduleExpressionTimezone="America/New_York"),), 24, "UNKNOWN"),
    ((rule("cron(0 5 L * ? *)", 35),), 744, "UNKNOWN"),
    ((rule("cron(0 5 ? * * 2030)", 35),), 24, "UNKNOWN"),
    ((rule("cron(0 5 ? * FRI-MON *)", 35),), 168, "UNKNOWN"),          # wrapping range
    ((rule(DAILY, None, Lifecycle={"DeleteAfterEvent": "DELETED"}),), 24, "UNKNOWN"),
    ((rule("cron(0 5 ? * MON *)", 35, EnableContinuousBackup=True),), 24, "UNKNOWN"),  # PITR coverage not proven
    ((rule(DAILY, 34), rule("rate(1 day)", 35)), 24, "UNKNOWN"),       # no proven qualifier, one unresolved
    ((rule(None, 35),), 24, "UNKNOWN"),                                 # missing schedule is never defaulted
    ((rule(DAILY, 0),), 24, "UNKNOWN"),                                 # invalid DeleteAfterDays
    ((rule(DAILY, -1),), 24, "UNKNOWN"),                                # removal sentinel needs verified GetBackupPlan semantics
    ((rule(DAILY, True),), 24, "UNKNOWN"),                              # bool is not an int day count
])
def test_rule_quantifier_and_bounds(rules, hours, expected):
    item = plan(*rules)
    outcome, evidence = status(item, index(item, policy(hours)))
    assert outcome == expected, evidence
    if outcome in ("PASS", "FAIL"):
        assert evidence["quantifier"] == "at_least_one_rule" and evidence["required_retention_days"] == 35
        assert evidence["required_frequency_hours"] == hours and evidence["frequency_policy_source"] == "operator-supplied"
        assert evidence["semantics"].startswith("configured schedule and lifecycle coverage only")


def test_continuous_rule_that_meets_by_schedule_still_qualifies():
    item = plan(rule(DAILY, 35, EnableContinuousBackup=True))
    assert status(item)[0] == "PASS"


def test_denied_rule_fields_are_unresolved_not_failures():
    item = plan(rule(DAILY, 35))
    item["Plan"]["BackupPlan"]["Rules"][0]["_coverage"] = {"Lifecycle": {"status": "denied"}}
    assert status(item)[0] == "UNKNOWN"
    item = plan(rule(DAILY, 35), rule(DAILY, 35))
    item["Plan"]["BackupPlan"]["Rules"][1]["_coverage"] = {"ScheduleExpression": {"status": "denied"}}
    assert status(item)[0] == "PASS"


def test_calendar_cache_stays_bounded():
    backup.max_day_gap.cache_clear()
    item = plan(*(rule(f"cron(0 5 {day} * ? *)", 35) for day in range(1, 29)))
    assert status(item, index(item, policy(744)))[0] == "PASS"
    info = backup.max_day_gap.cache_info()
    assert info.maxsize == 256 and info.currsize <= 28


# ------------------------------------------------------------------ operator policy input at evaluation

@pytest.mark.parametrize("body", [
    None,                                               # no declaration: never defaulted
    policy(status="unknown"),
    policy(source="observed"),
    policy(applies=("999999999999/eu-west-1",)),        # does not cover this scope
    policy(applies=("*",)),                             # no wildcard coverage
    policy(hours=True), policy(hours=0), policy(hours=-1), policy(hours=745), policy(hours=math.nan),
    policy(hours=math.inf), policy(hours="24"), policy(hours=None),
    "not-an-object",
])
def test_missing_or_invalid_policy_is_unknown(body):
    item = plan(rule(DAILY, 35))
    outcome, evidence = status(item, index(item, body))
    assert outcome == "UNKNOWN", evidence


def test_policy_without_applies_to_is_unknown():
    item = plan(rule(DAILY, 35))
    body = policy()
    del body["applies_to"]
    assert status(item, index(item, body))[0] == "UNKNOWN"


# ------------------------------------------------------------------ scope and identity errors

@pytest.mark.parametrize("arn", [
    f"arn:aws:backup:us-east-1:{ACCOUNT}:plan:{PLAN_ID}",          # other Region
    f"arn:aws:backup:{REGION}:111111111111:plan:{PLAN_ID}",         # other account
    f"arn:aws-cn:backup:{REGION}:{ACCOUNT}:plan:{PLAN_ID}",         # other partition
    f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{PLAN_ID}",    # not a plan
])
def test_foreign_or_malformed_plan_arn_is_unknown(arn):
    item = plan(rule(DAILY, 35), arn=arn)
    assert status(item)[0] == "UNKNOWN"


def test_both_documented_plan_arn_spellings_are_accepted():
    item = plan(rule(DAILY, 35), arn=f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:{PLAN_ID}")
    assert status(item)[0] == "PASS"


def test_inventory_identity_and_detail_errors_are_unknown():
    item = plan(rule(DAILY, 35))
    other = copy.deepcopy(item)
    other["BackupPlanName"] = "different"
    assert status(item, index(other))[0] == "UNKNOWN"                       # absent from complete scoped inventory
    assert status(item, index(item, status="partial"))[0] == "UNKNOWN"      # incomplete inventory
    assert status(item, index(item, callers=[]))[0] == "UNKNOWN"            # no audited partition
    for detail in ({"collection_status": "denied"}, "malformed"):
        broken = dict(item, Plan=detail)
        assert status(broken)[0] == "UNKNOWN"
    deleted = plan(rule(DAILY, 35), DeletionDate="2026-01-01T00:00:00Z")
    assert status(deleted)[0] == "UNKNOWN"
    mismatched = plan(rule(DAILY, 35))
    mismatched["Plan"]["BackupPlanArn"] = f"arn:aws:backup:{REGION}:{ACCOUNT}:plan:other"
    assert status(mismatched)[0] == "UNKNOWN"


# ------------------------------------------------------------------ collector ingestion (operator declaration)

def test_collector_records_a_validated_declaration_only():
    declared = aws_policy.backup_plan_policy({"compliance_policy": {"aws_backup_plan": {
        "applies_to": ["123456789012/us-east-1", SCOPE], "required_frequency_hours": 24}}})
    assert declared == {"status": "collected", "source": "operator-supplied", "basis": aws_policy.BASIS,
                        "applies_to": [SCOPE, "123456789012/us-east-1"], "required_frequency_hours": 24}
    bound = aws_policy.bind_backup_plan_policy(declared, [SCOPE])
    assert bound["unmatched_scopes"] == ["123456789012/us-east-1"] and bound["applies_to"] == declared["applies_to"]
    from peaso.collectors.aws import _safe
    assert _safe({"compliance_policy": {"aws_backup_plan": bound}}) == {"compliance_policy": {"aws_backup_plan": bound}}
    assert aws_policy.backup_plan_policy({}) is None
    assert aws_policy.backup_plan_policy({"compliance_policy": {"other": {}}}) is None


@pytest.mark.parametrize("options", [
    {"compliance_policy": []},
    {"compliance_policy": {"aws_backup_plan": []}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE]}}},
    {"compliance_policy": {"aws_backup_plan": {"required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE], "required_frequency_hours": 24, "required_retention_days": 35}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE, SCOPE], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": ["*"], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [ACCOUNT], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [[SCOPE]], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE] * 2 + ["x"] * 999, "required_frequency_hours": 24}}},
    *({"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE], "required_frequency_hours": value}}}
      for value in (True, 0, -1, 745, math.nan, math.inf, "24", None)),
])
def test_collector_rejects_malformed_declarations(options):
    with pytest.raises(ValueError):
        aws_policy.backup_plan_policy(options)


def test_collector_validates_before_any_aws_request_and_seals_policy_in_metadata():
    source = (ROOT / "peaso/collectors/aws.py").read_text()
    validated = source.index("    backup_policy = backup_plan_policy(options)\n")
    assert validated < source.index("    selected_accounts, regions = _selection(connector)\n")
    sealed = source.index('        metadata["compliance_policy"] = {"aws_backup_plan": bind_backup_plan_policy(backup_policy, scopes)}\n')
    final = source.index('    return make_snapshot("aws", scopes, collections, created_at=requests.observed_at.isoformat(), metadata=_safe(metadata))\n')
    assert source.index("    scopes = sorted(") < sealed < final
    assert source.count(" backup_plan_policy(") == 1 and source.count("bind_backup_plan_policy(") == 1


# ------------------------------------------------------------------ end to end through the engine

def snapshot_for(plans_by_scope, body):
    collections = [{"type": "backup_plan", "scope": scope, "service": "backup", "status": "collected", "items": items}
                   for scope, items in plans_by_scope.items()]
    metadata = {"caller_identities": [{"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Audit/peaso-read-only"}]}
    if body is not None:
        metadata["compliance_policy"] = {"aws_backup_plan": body}
    return make_snapshot("aws", sorted(plans_by_scope), collections, created_at="2026-10-13T00:00:00+00:00", metadata=metadata)


def findings(snapshot):
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CID])
    return sorted(report["findings"], key=lambda row: (row["scope"], row["resource_id"]))


def test_engine_evaluates_each_scope_with_its_own_declaration_without_duplicates():
    east = "123456789012/us-east-1"
    east_arn = f"arn:aws:backup:us-east-1:{ACCOUNT}:plan:{PLAN_ID}"
    snapshot = snapshot_for({SCOPE: [plan(rule(DAILY, 35))], east: [plan(rule(DAILY, 35), arn=east_arn)]}, policy(24, (SCOPE,)))
    rows = findings(snapshot)
    assert {row["scope"]: row["status"] for row in rows} == {east: "UNKNOWN", SCOPE: "PASS"}
    assert len({row["id"] for row in rows}) == 2 and rows == findings(snapshot)  # deterministic, deduplicated
    assert all(row["check_id"] == CID for row in rows)
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CID])
    assert report["check_meta"][CID]["category"] == "hardening"


def test_engine_without_declaration_is_unknown_and_declaration_is_sealed():
    without = snapshot_for({SCOPE: [plan(rule(DAILY, 35))]}, None)
    assert [row["status"] for row in findings(without)] == ["UNKNOWN"]
    declared = snapshot_for({SCOPE: [plan(rule(DAILY, 35))]}, policy())
    assert declared["snapshot_id"] != without["snapshot_id"]
    tampered = copy.deepcopy(declared)
    tampered["metadata"]["compliance_policy"]["aws_backup_plan"]["required_frequency_hours"] = 744
    with pytest.raises(ValueError):
        validate(tampered)
