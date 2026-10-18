"""Azure NSG declaration-audit gap natives and the verified-only Azure corrected-merge contract."""
import copy
import glob
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, azure_gap_nsg as gap
from peaso.checks.claude_azure_common import nsg_case, nsg_rule
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = {check.id: check for check in CHECKS}
SHADOW = nsg_rule("deny-internet", "*", "Internet", "*", access="Deny")


def _status(cid, *rules):
    return REGISTRY[cid].evaluate(nsg_case(*rules), {})[0]


@pytest.mark.parametrize("cid", gap.CHECK_IDS, ids=str)
def test_fixture_pass_fail_and_input_not_mutated(cid):
    for label, expected in (("pass", "PASS"), ("fail", "FAIL")):
        item = copy.deepcopy(CASES[cid][label])
        before = copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item, {})[0] == expected
        assert item == before
    for item in ({}, None, {"properties": {}}):
        assert REGISTRY[cid].evaluate(item, {})[0] == "UNKNOWN"


def test_declaration_semantics_ignore_higher_priority_deny_and_outbound_or_trusted_sources():
    rdp = gap.SOURCE_QUERIES["network_security_group_rdp_access_restricted"]
    assert _status(rdp, SHADOW, nsg_rule("open", "Tcp", "0.0.0.0/0", "3389")) == "FAIL"
    assert _status(rdp, nsg_rule("open", "*", ["10.0.0.0/8", "Internet"], ["22", "3000-4000"])) == "FAIL"
    assert _status(rdp, nsg_rule("out", "Tcp", "Internet", "3389", direction="Outbound")) == "PASS"
    assert _status(rdp, nsg_rule("deny", "Tcp", "Internet", "3389", access="Deny")) == "PASS"
    assert _status(rdp, nsg_rule("udp", "Udp", "Internet", "3389")) == "PASS"
    assert _status(rdp, nsg_rule("trusted", "Tcp", "203.0.113.0/24", "*")) == "PASS"
    assert _status(rdp, nsg_rule("bad", "Tcp", "Internet", "33x89")) == "UNKNOWN"


def test_upstream_port_defects_are_corrected_not_reproduced():
    udp = gap.SOURCE_QUERIES["network_security_group_udp_service_restricted"]
    both = gap.SOURCE_QUERIES["network_security_group_https_port_80_443_access_restricted"]
    http = gap.SOURCE_QUERIES["network_security_group_https_access_restricted"]
    assert _status(udp, nsg_rule("dns", "Udp", "Internet", "53")) == "FAIL"  # source omitted exact ports
    assert _status(udp, nsg_rule("ntp", "*", "*", "123")) == "FAIL"
    assert _status(udp, nsg_rule("tcp", "Tcp", "*", "53")) == "PASS"
    assert _status(both, nsg_rule("web", "Tcp", "Internet", "80-81")) == "FAIL"  # source required 80 AND 443 in one range
    assert _status(both, nsg_rule("tls", "Tcp", "Internet", "443")) == "FAIL"
    assert _status(http, nsg_rule("tls", "Tcp", "Internet", "443")) == "PASS"
    remote = gap.SOURCE_QUERIES["network_security_group_remote_access_restricted"]
    assert _status(remote, SHADOW, nsg_rule("ssh", "Tcp", "Internet", "22")) == "FAIL"
    assert _status(remote, nsg_rule("web", "Tcp", "Internet", "443")) == "PASS"


def test_prowler_udp_any_and_singular_field_defects_are_corrected():
    udp = gap.PROWLER_SOURCES["prowler.azure.network_udp_internet_access_restricted"]
    rdp = gap.PROWLER_SOURCES["prowler.azure.network_rdp_internet_access_restricted"]
    assert _status(udp, SHADOW, nsg_rule("hi", "Udp", "Internet", "40000")) == "FAIL"
    assert _status(udp, nsg_rule("any", "*", ["10.0.0.0/8", "0.0.0.0/0"], ["9000-9100"])) == "FAIL"  # plural fields + Any
    assert _status(udp, nsg_rule("tcp", "Tcp", "Internet", "*")) == "PASS"
    assert _status(udp, nsg_rule("bad", "Udp", "Internet", "x")) == "UNKNOWN"
    assert _status(rdp, nsg_rule("all", "Tcp", "Internet", "*")) == "FAIL"  # Prowler misses port '*'


def _azure_rows():
    for path in sorted(glob.glob(str(ROOT / "peaso/rulepacks/reviewed_azure*.json")) + [str(ROOT / "peaso/rulepacks/reviewed_claude_azure.json")]):
        for sid, row in json.loads(Path(path).read_text()).items():
            yield Path(path).name, sid, row


def test_every_azure_corrected_merge_has_recorded_same_requirement_verification():
    merged = [(shard, sid, row) for shard, sid, row in _azure_rows() if row.get("review_classification") == "corrected_native_merge"]
    assert len(merged) == 162  # 152 rejected-then-verified rows + 10 NSG declaration-audit rows repointed from priority-aware natives
    for shard, sid, row in merged:
        v = row["native_equivalence_verification"]
        assert row["disposition"] == "merged" and row["upstream_defect"]["reason"], sid
        assert v["verdict"] == "same_control_requirement" and v["target_native_checks"] == row["native_checks"], sid
        assert set(row["native_checks"]) <= set(REGISTRY), sid
        assert v["query_id"] == row["source_review"].get("query_id", sid.rsplit(".", 1)[-1]), sid
        assert all(v[k] for k in ("resource", "property", "pass_condition", "upstream_defect_only")), sid
    # Verification records never appear on rows that were not merged.
    assert not [sid for _, sid, row in _azure_rows() if "native_equivalence_verification" in row and row.get("review_classification") != "corrected_native_merge"]


def test_merged_rows_carry_frameworks_to_target_natives():
    manifest = {row["check_id"]: row for row in json.loads((ROOT / "peaso/rulepacks/upstream_manifest.json").read_text())["checks"]}
    for _, sid, row in _azure_rows():
        if row.get("review_classification") == "corrected_native_merge":
            assert manifest[sid]["disposition"] == "merged" and manifest[sid]["native_checks"] == row["native_checks"]
    linked = {n for r in manifest.values() if r["disposition"] in ("ported", "merged") and r["frameworks"] for n in r["native_checks"]}
    assert set(gap.CHECK_IDS) <= linked


def test_nsg_declaration_controls_target_strict_natives_and_exposure_natives_carry_no_compliance_labels():
    from peaso.checks.catalog import framework_ids_for
    rows = json.loads((ROOT / "peaso/rulepacks/upstream_manifest.json").read_text())["checks"]
    for row in rows:
        if row["disposition"] in ("ported", "merged"):
            assert not set(row["native_checks"]) & set(gap.EXPOSURE_ONLY_NATIVES), row["check_id"]
    for cid in gap.EXPOSURE_ONLY_NATIVES:
        check = REGISTRY[cid]
        assert check.category == "exposure" and not framework_ids_for(cid), cid
    targets = {row["check_id"]: row["native_checks"] for row in rows}
    for sid, cid in gap.PROWLER_SOURCES.items():
        assert targets[sid] == [cid], sid
    for query, cid in gap.SOURCE_QUERIES.items():
        assert targets["azure-compliance.control." + query] == [cid], query
