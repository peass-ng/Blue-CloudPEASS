"""Compile verified compliance research into immutable runtime metadata.

No upstream source is executed. A supervisor manifest, pinned audit matrix,
and the complete set of verified review files are required before writing.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import sys


DECISIONS = {"MAPPED", "MAPPING_FIX", "PARTIAL", "MANUAL", "NOT_APPLICABLE", "NEW_CHECK"}
PROVIDERS = {"aws", "gcp", "azure", "k8s"}
# Exact signed duplicate: keep historical proposal, score its one control on the existing predicate.
REVIEWED_EQUIVALENT_PROPOSAL = {
    "id": "aws_g6_redshift_automatic_version_upgrade",
    "survivor": "aws.cb.redshift.allow_version_upgrade",
    "framework_id": "aws-compliance.benchmark.nist_csf_v2",
    "requirement_id": "aws-compliance.control.redshift_cluster_automatic_upgrade_major_versions_enabled",
    "spec_sha256": "ad979ddc6088494278a5100080090a456ab9d01e0cea7ff54e7e33bc4e5badb3",
}
REVIEWED_CLOUDTRAIL_EQUIVALENT = {
    "id": "aws.pci.cloudtrail.authentication_events",
    "survivor": "aws.gap.cloudtrail.region_logging_management_events",
    "spec_sha256": "f3b62c9ae56b850f165b1eb80a1244adb8854b9be2e8671f1d9e0c575f9bd9a1",
    "source_sha256": "6830c3b72df05ae820d9bd96b04dc7741708bb2d29aa30a8e1b3816d397a6fda",
    "rows": frozenset({
        ("pci_3.2.1_aws", "10.2.5"),
        ("pci_3.2.1_aws", "10.2.5.a"),
        ("fedramp_low_revision_4_aws", "au-2"),
        ("fedramp_moderate_revision_4_aws", "au-2-a-d"),
        ("nist_800_53_revision_4_aws", "au_2"),
        ("nist_800_53_revision_5_aws", "au_12_a"),
        ("nist_800_53_revision_5_aws", "au_12_c"),
    }),
}
# Evidence-only successor: _trail_scan adds decisive FAIL evidence; all status
# paths and 138 original/current registered-fixture outcomes remain unchanged.
# Keep the historical whole-file pin and reject any unlisted successor.
REVIEWED_CLOUDTRAIL_RUNTIME_SUCCESSORS = {
    "6830c3b72df05ae820d9bd96b04dc7741708bb2d29aa30a8e1b3816d397a6fda": frozenset({
        "adc455960545fafeda8f73855c5612e80290541b72e1117f026082deabf246b4",
    }),
}
REVIEWED_RDS_CLUSTER_EQUIVALENT = {
    "id": "aws_fedramp_rds_cluster_members_enhanced_monitoring",
    "survivor": "aws.nist.rds_cluster_member_enhanced_monitoring",
    "spec_sha256": "0f0a82a629b961c7cff07771a5e9d4f44a9fb0944a104b27fd0a723b67a97160",
    "survivor_spec_sha256": "e8bad74aaeac0443e90653f07bff27965c721c3dd3f60b8f84d4c4fd7654a086",
    "source_sha256": "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9",
    "rows": frozenset({
        ("aws-compliance.benchmark.fedramp_low_rev_4", "aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled"),
        ("aws-compliance.benchmark.fedramp_moderate_rev_4", "aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled"),
    }),
}
# This reviewed native evidence successor retains the exact RDS callback and
# strengthens the common raw-inventory identity guard. Preserve the original
# frozen module pin and admit only this explicitly reviewed whole-file successor.
REVIEWED_RDS_RUNTIME_SUCCESSORS = {
    "ded9f2aa60b562cc3db565a091434ad182e8ae8635d4b128549b827a39a6f5f9": frozenset({
        "2a87f6c990065271ae9eaa9c34582d64297554eaf183f81c5a566eeb0cd8ac72",
    }),
}
DESCRIPTION_FIELD_ORDER = ("description", "fail_when", "evaluated", "not_applicable_when", "pass_when")
DESCRIPTION_FIELDS = set(DESCRIPTION_FIELD_ORDER)
ANALYSIS_IDS = {"analysis.grant_review", "analysis.inactive_identity", "analysis.principal_exposure",
                "analysis.network_review", "analysis.coverage", "analysis.internet_exposure", "analysis.federated_trust"}
SOURCE_ERRATA = {
    "gcp-api-key-service-name-erratum-20261018.json": (
        "gcp.apikeys.active_service_restrictions",
        "0cae3df2c44dcab5f9ce736977ff4a191d83dba2406161be7fb1cdb1a959dd31",
        "fe2e9bd7e9f6bde4af987a6a3ca40d358cbf24bef3541506c25233b5a7146eb9"),
}
RESEARCH_JSON = {f"new-checks-{provider}.json" for provider in PROVIDERS} | set(SOURCE_ERRATA) | {
    "descriptions/desc-all-1.problems.json", "descriptions/desc-aws-2.problems.json",
    "descriptions/desc-azure-2.problems.json", "descriptions/desc-gcp-1.problems.json",
    "descriptions/desc-k8s-2.problems.json",
    "provenance/aws_config_all_resources_recorded.superseded-8f9c88b1.json",
    "provenance/aws_nist_backup_plan_min_retention_35_days.superseded-4ce264ac.json",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def spec_digest(value: dict) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def verify_source_errata(ledger_root, native):
    """Keep historical ledgers valid; require exact bytes for admitted successors."""
    for relative, (check_id, spec_sha256, file_sha256) in SOURCE_ERRATA.items():
        path = ledger_root / relative
        provenance = native.get(check_id, {}).get("proposal_provenance", {})
        correction = provenance.get("source_correction", {})
        required = correction.get("current_canonical_spec_sha256") == spec_sha256
        if required and not path.is_file():
            raise ValueError("Admitted source erratum is missing")
        if path.exists():
            path = checked_path(ledger_root, relative)
            if digest(path.read_bytes()) != file_sha256:
                raise ValueError("Source erratum hash mismatch")


def _reviewed_rds_registered_declaration(native):
    """Permit the first compile's minimal seed only with exact live source proof."""
    from peaso.checks import CHECKS, CHECK_ALIASES
    expected = REVIEWED_RDS_CLUSTER_EQUIVALENT
    survivor = expected["survivor"]
    actual = native.get(survivor, {})
    source = Path(__file__).resolve().parent.parent / "peaso/checks/remaining_aws_gcp_native.py"
    registered = [check for check in CHECKS if check.id == survivor]
    from peaso.finding_priority import source_priority
    wanted = {"provider": "aws", "type": "rds_cluster", "category": "hardening", "severity": "medium", "target": "resource"}
    if (len(registered) != 1 or actual.get("id") != survivor or actual.get("provider") != "aws" or
            expected["id"] in native or CHECK_ALIASES.get(expected["id"]) != survivor or
            digest(source.read_bytes()) not in ({expected["source_sha256"]} |
                REVIEWED_RDS_RUNTIME_SUCCESSORS.get(expected["source_sha256"], frozenset())) or
            any(field in actual and (source_priority(actual) if field == "severity" else actual[field]) != value for field, value in wanted.items())):
        raise ValueError("Reviewed RDS duplicate registration or source changed")
    check = registered[0]
    if ((check.provider, check.kind, check.category, check.severity, check.target, tuple(check.declared_dependencies)) !=
            ("aws", "rds_cluster", "hardening", "medium", "resource", ("rds_cluster", "rds_instance"))):
        raise ValueError("Reviewed RDS survivor declaration changed")
    function = getattr(check.evaluate, "__wrapped__", None)
    if (function is None or function.__module__ != "peaso.checks.remaining_aws_gcp_native" or
            function.__name__ != "rds_cluster_member_monitoring" or
            Path(function.__code__.co_filename).resolve() != source.resolve()):
        raise ValueError("Reviewed RDS survivor callback source changed")


def _reviewed_rds_signed_specs(proposed):
    expected = REVIEWED_RDS_CLUSTER_EQUIVALENT
    for cid, wanted in ((expected["id"], expected["spec_sha256"]),
                        (expected["survivor"], expected["survivor_spec_sha256"])):
        spec = proposed.get(cid)
        if not isinstance(spec, dict) or len(spec) != 10 or spec_digest(spec) != wanted:
            raise ValueError("Reviewed RDS alias or survivor signed proposal changed")


def reviewed_equivalent_proposal(spec: dict, framework_id: str, requirement_id: str,
                                 native: dict) -> str | None:
    """Return a reviewed existing evaluator for an exact signed duplicate."""
    from peaso.finding_priority import source_priority
    expected_rds = REVIEWED_RDS_CLUSTER_EQUIVALENT
    if spec["id"] == expected_rds["id"]:
        survivor = expected_rds["survivor"]
        if survivor not in native:
            return None  # Unregistered signed proposal remains pending.
        if ((framework_id, requirement_id) not in expected_rds["rows"] or
                len(spec) != 10 or spec_digest(spec) != expected_rds["spec_sha256"]):
            raise ValueError("Reviewed RDS duplicate signed row changed")
        _reviewed_rds_registered_declaration(native)
        return survivor
    if spec["id"] == REVIEWED_CLOUDTRAIL_EQUIVALENT["id"]:
        expected = REVIEWED_CLOUDTRAIL_EQUIVALENT
        survivor = expected["survivor"]
        actual = native.get(survivor, {})
        source = Path(__file__).resolve().parent.parent / "peaso/checks/aws_gap_core.py"
        if ((framework_id, requirement_id) not in expected["rows"] or
                spec_digest(spec) != expected["spec_sha256"] or
                (spec["provider"], spec["resource_kind"], spec["category"], spec["severity"]) !=
                ("aws", "cloudtrail_trail", "logging", "medium") or
                (actual.get("provider"), actual.get("type"), actual.get("category"),
                 source_priority(actual), actual.get("target")) !=
                ("aws", "cloudtrail", "hardening", "high", "scope") or
                digest(source.read_bytes()) not in ({expected["source_sha256"]} |
                    REVIEWED_CLOUDTRAIL_RUNTIME_SUCCESSORS.get(expected["source_sha256"], frozenset())) or spec["id"] in native):
            raise ValueError("Reviewed CloudTrail duplicate proposal changed")
        return survivor
    expected = REVIEWED_EQUIVALENT_PROPOSAL
    if spec["id"] != expected["id"]:
        return None
    survivor = expected["survivor"]
    actual = native.get(survivor, {})
    if (framework_id != expected["framework_id"] or requirement_id != expected["requirement_id"] or
            spec_digest(spec) != expected["spec_sha256"] or
            actual.get("provider") != spec["provider"] or
            actual.get("type") != spec["resource_kind"] or
            actual.get("category") != spec["category"] or
            source_priority(actual) != spec["severity"] or
            actual.get("target") != "resource" or spec["id"] in native):
        raise ValueError("Reviewed Redshift duplicate proposal changed")
    return survivor


def catalog_with_registered_checks(native_catalog: dict, checks) -> dict:
    """Include newly registered predicates before their public catalog is rebuilt.

    The verified ledger still decides whether those new IDs may be compiled.
    Existing catalog IDs and providers must agree with the live registry.
    """
    stored = native_catalog.get("checks")
    if not isinstance(stored, list):
        raise ValueError("Native catalogue has no checks")
    indexed = {row["id"]: row for row in stored}
    registered = {check.id: check for check in checks}
    if len(indexed) != len(stored) or len(registered) != len(checks):
        raise ValueError("Duplicate native check ID")
    if not set(indexed) <= set(registered):
        raise ValueError("Native catalogue contains an unregistered check")
    if any(row.get("provider") != registered[cid].provider for cid, row in indexed.items()):
        raise ValueError("Native catalogue provider differs from registry")
    from peaso.finding_priority import source_priority
    for cid, row in indexed.items():
        if "severity_review" in row:
            source_severity = source_priority(row)
            if source_severity != getattr(registered[cid], "severity", None):
                raise ValueError("Native catalogue signed source priority differs from registry")
    additions = [{"id": cid, "provider": registered[cid].provider, "title": registered[cid].title}
                 for cid in sorted(set(registered) - set(indexed))]
    return {**native_catalog, "checks": [*stored, *additions]}


def read_json(path: Path):
    return strict_json(path.read_bytes())


def strict_json(raw: bytes):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate key in verified JSON: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=no_duplicates)


def checked_path(root: Path, value: str, *, prefix: str = "") -> Path:
    if not isinstance(value, str) or not value.endswith(".json") or value.startswith("/") or "\\" in value:
        raise ValueError("Invalid ledger path")
    parts = Path(value).parts
    if any(part in {"", ".", ".."} for part in parts) or (prefix and not value.startswith(prefix)):
        raise ValueError("Ledger path escapes the verified root")
    path = root.joinpath(*parts)
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("Verified ledger file is missing or escapes the root")
    return path


def verified_file(root: Path, entry: dict, *, prefix: str = ""):
    if not isinstance(entry, dict) or entry.get("verified") is not True:
        raise ValueError("Unverified ledger entry")
    path = checked_path(root, entry.get("path"), prefix=prefix)
    raw = path.read_bytes()
    if digest(raw) != entry.get("sha256"):
        raise ValueError("Verified ledger hash mismatch: " + str(entry.get("path")))
    return strict_json(raw), path


def require_fields(value: dict, fields: set, context: str):
    if not isinstance(value, dict) or not fields <= value.keys():
        raise ValueError("Missing fields in " + context)


def matrix_from(path: Path):
    raw = path.read_bytes()
    return strict_json(gzip.decompress(raw) if path.suffix == ".gz" else raw)


def coverage_matrix(audit_matrix: dict, requirements_pack: dict):
    """Compare source-reference inventory with reviewed requirement states, never certification."""
    before = {row["id"]: row for row in audit_matrix["frameworks"]}
    rows = []
    for framework in requirements_pack["frameworks"]:
        requirements = framework["requirements"]
        after = dict(sorted(Counter(row["runtime_status"] for row in requirements).items()))
        ids_by_state = {state: [row["requirement_id"] for row in requirements if row["runtime_status"] == state]
                        for state in sorted(after)}
        pending = [row["requirement_id"] for row in requirements if row["pending_checks"]]
        rows.append({"id": framework["id"], "name": framework["name"], "provider": framework["provider"],
                     "requirements_total": framework["requirements_total"],
                     "before_source_reference_counts": before[framework["id"]]["counts"],
                     "after_reviewed_requirement_counts": after,
                     "requirement_ids_by_state": ids_by_state,
                     "unique_implemented_native_checks": len({cid for row in requirements for cid in row["native_checks"]}),
                     "pending_automatable_requirement_ids": pending,
                     "pending_automatable_requirements": len(pending)})
    return {"meaning": "Requirement mappings and support states, not account compliance or certification",
            "frameworks": rows, "frameworks_total": len(rows),
            "requirements_total": sum(row["requirements_total"] for row in rows),
            "unique_implemented_native_checks": len(requirements_pack["by_check"]),
            "pending_automatable_requirements": sum(row["pending_automatable_requirements"] for row in rows),
            "hacktricks_best_practices": requirements_pack["hacktricks_best_practices"]}


def lookup_index(requirements_pack: dict, full_pack_sha256: str) -> dict:
    """Small ordinary-path index; the canonical pack retains all source evidence."""
    summaries = []
    for framework in requirements_pack["frameworks"]:
        rows = framework["requirements"]
        summaries.append({"id": framework["id"], "name": framework["name"],
                          "provider": framework["provider"], "requirements_total": framework["requirements_total"],
                          "requirements_by_status": dict(sorted(Counter(row["runtime_status"] for row in rows).items())),
                          "pending_automatable_requirements": sum(bool(row["pending_checks"]) for row in rows)})
    proposals = [{"id": spec["id"], "provider": spec["provider"], "severity": spec["severity"],
                  "category": spec["category"], "resource_kind": spec["resource_kind"],
                  "signed_spec_sha256": spec_digest(spec)} for spec in requirements_pack["proposed_checks"]]
    return {"schema_version": requirements_pack["schema_version"],
            "source_manifest_sha256": requirements_pack["source_manifest_sha256"],
            "full_pack_sha256": full_pack_sha256, "frameworks": summaries,
            "by_check": requirements_pack["by_check"], "proposed_checks": proposals,
            "counts": requirements_pack["counts"],
            "hacktricks_best_practices": requirements_pack["hacktricks_best_practices"]}


def compile_verified(ledger_root: Path, audit_matrix: dict, native_catalog: dict):
    """Return (requirement pack, description pack); raise before any output on partial input."""
    ledger_root = ledger_root.resolve()
    manifest_path = ledger_root / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Supervisor compliance ledger manifest is missing")
    manifest = read_json(manifest_path)
    require_fields(manifest, {"version", "check_index_sha256", "slices", "descriptions"}, "manifest")
    if manifest["version"] != 1 or not isinstance(manifest["slices"], dict) or not isinstance(manifest["descriptions"], dict):
        raise ValueError("Unsupported or partial compliance manifest")
    index_path = checked_path(ledger_root, "inputs/check-index.json", prefix="inputs/")
    if digest(index_path.read_bytes()) != manifest["check_index_sha256"]:
        raise ValueError("Check-index snapshot hash mismatch")
    index = read_json(index_path)
    if not isinstance(index, list) or len({row.get("id") for row in index if isinstance(row, dict)}) != len(index):
        raise ValueError("Check-index IDs are not unique")
    indexed = {row["id"]: row for row in index}
    native_rows = native_catalog.get("checks")
    if not isinstance(native_rows, list):
        raise ValueError("Native catalogue has no checks")
    native = {row["id"]: row for row in native_rows}
    verify_source_errata(ledger_root, native)
    if len(native) != len(native_rows):
        raise ValueError("Native catalogue IDs are not unique")
    new_native = set(native) - set(indexed)
    for cid in ANALYSIS_IDS & set(indexed):
        if indexed[cid].get("provider") != "all" or cid in native:
            raise ValueError("Analysis check metadata is malformed")
        native[cid] = indexed[cid]
    matrix_rows = audit_matrix.get("frameworks")
    if not isinstance(matrix_rows, list):
        raise ValueError("Pinned audit matrix has no frameworks")
    thematic = audit_matrix.get("hacktricks_best_practices")
    if not isinstance(thematic, dict) or thematic.get("requirements_total", "missing") is not None or not thematic.get("reason"):
        raise ValueError("Pinned thematic guidance status is missing")
    matrix = {row["id"]: row for row in matrix_rows}
    if len(matrix) != len(matrix_rows):
        raise ValueError("Pinned audit matrix framework IDs are not unique")

    # Extra JSON outside inputs and the manifest cannot silently masquerade as accepted work.
    listed = {entry.get("path") for entry in list(manifest["slices"].values()) + list(manifest["descriptions"].values()) if isinstance(entry, dict)}
    supplement_entry = manifest.get("new_descriptions")
    if supplement_entry is not None:
        if not isinstance(supplement_entry, dict) or supplement_entry.get("path") != "descriptions/implemented-new-checks.json":
            raise ValueError("Unexpected supplemental description path")
        listed.add(supplement_entry["path"])
    actual = {path.relative_to(ledger_root).as_posix() for path in ledger_root.rglob("*.json")
              if "inputs" not in path.relative_to(ledger_root).parts and ".work" not in path.relative_to(ledger_root).parts
              and path.name != "manifest.json"
              and path.relative_to(ledger_root).as_posix() not in RESEARCH_JSON}
    if actual != listed:
        raise ValueError("Unlisted or missing compliance ledger JSON files")

    frameworks = {}
    by_check = defaultdict(list)
    proposed = {}
    equivalent_seen = set()
    for slice_name, entry in sorted(manifest["slices"].items()):
        if not isinstance(slice_name, str) or not slice_name or "/" in slice_name:
            raise ValueError("Invalid ledger slice name")
        if entry.get("path") != slice_name + ".json":
            raise ValueError("Slice path does not match its manifest name")
        ledger, _ = verified_file(ledger_root, entry)
        input_name = "inputs/" + slice_name + ".json"
        frozen_path = checked_path(ledger_root, input_name, prefix="inputs/")
        frozen = read_json(frozen_path)
        if digest(frozen_path.read_bytes()) != entry.get("input_sha256") or ledger.get("generated_from") != input_name or ledger.get("slice") != slice_name:
            raise ValueError("Ledger input provenance mismatch: " + slice_name)
        if frozen.get("slice") != slice_name or not isinstance(ledger.get("frameworks"), list):
            raise ValueError("Malformed ledger slice")
        expected = {row["id"]: row for row in frozen["frameworks"]}
        reviewed = {row["id"]: row for row in ledger["frameworks"]}
        if len(reviewed) != len(ledger["frameworks"]) or set(reviewed) != set(expected):
            raise ValueError("Ledger framework coverage differs from frozen input")
        count = 0
        for framework_id, source in expected.items():
            if framework_id in frameworks or framework_id not in matrix:
                raise ValueError("Duplicate or unknown framework ID: " + framework_id)
            reviewed_framework = reviewed[framework_id]
            if source["provider"] not in PROVIDERS or reviewed_framework.get("provider") != source["provider"]:
                raise ValueError("Framework provider mismatch")
            source_items = {row["id"]: row for row in source["requirements"]}
            pinned_items = {row["id"]: row for row in matrix[framework_id]["requirements"]}
            if source_items != pinned_items or source["name"] != matrix[framework_id]["name"] or source["provider"] != matrix[framework_id]["provider"]:
                raise ValueError("Frozen ledger input differs from pinned audit matrix")
            rows = reviewed_framework.get("requirements")
            if not isinstance(rows, list) or len(rows) != len(source_items) or len({row.get("requirement_id") for row in rows if isinstance(row, dict)}) != len(rows):
                raise ValueError("Missing or duplicate requirement decision: " + framework_id)
            if {row["requirement_id"] for row in rows} != set(source_items):
                raise ValueError("Ledger requirement IDs differ from frozen source")
            compiled = []
            for row in rows:
                rid = row["requirement_id"]
                require_fields(row, {"name", "decision", "native_checks", "removed_checks", "reason", "evidence", "new_checks"}, framework_id + ":" + rid)
                source_item = source_items[rid]
                # Some pinned Prowler requirements have an empty Name. The
                # reviewed ledger supplies their human-readable title; a
                # nonempty pinned name must still match exactly.
                if (not isinstance(row["name"], str) or
                        (source_item["name"] and row["name"] != source_item["name"]) or
                        row["decision"] not in DECISIONS):
                    raise ValueError("Requirement name or decision mismatch: " + framework_id + ":" + rid)
                if not isinstance(row["reason"], str) or len(row["reason"].strip()) < 15 or not isinstance(row["evidence"], list) or not row["evidence"]:
                    raise ValueError("Decision lacks a specific reason or source evidence")
                if not all((isinstance(ref, str) and bool(ref)) or
                           (isinstance(ref, dict) and
                            all(isinstance(ref.get(field), str) and ref[field] for field in ("check_id", "source", "predicate")) and
                            isinstance(ref.get("line"), int) and ref["line"] > 0)
                           for ref in row["evidence"]):
                    raise ValueError("Invalid requirement evidence")
                if any(not isinstance(row[key], list) for key in ("native_checks", "removed_checks", "new_checks")):
                    raise ValueError("Malformed check lists")
                ids = row["native_checks"]
                if len(ids) != len(set(ids)) or any(not isinstance(cid, str) or not cid for cid in ids):
                    raise ValueError("Requirement has malformed native check IDs")
                proposed_ids = {spec.get("id") for spec in row["new_checks"] if isinstance(spec, dict)}
                if len(proposed_ids) != len(row["new_checks"]):
                    raise ValueError("Duplicate or malformed proposed check IDs in requirement")
                if any(cid not in native and cid not in proposed_ids for cid in ids):
                    raise ValueError("Requirement references an absent, unproposed native check")
                implemented_ids = [cid for cid in ids if cid in native]
                if (any(not isinstance(cid, str) or not cid for cid in row["removed_checks"]) or
                        (set(ids) | proposed_ids) & set(row["removed_checks"])):
                    raise ValueError("Rejected and accepted check lists conflict")
                if row["decision"] in {"MAPPED", "MAPPING_FIX"} and not implemented_ids:
                    raise ValueError("Automated decision has no native check")
                if row["decision"] in {"MAPPED", "MAPPING_FIX"} and row["new_checks"]:
                    raise ValueError("Existing-check decision contains an unresolved new check")
                if row["decision"] in {"MANUAL", "NOT_APPLICABLE"} and ids:
                    raise ValueError("Manual/out-of-scope decision must not claim an automatic pass")
                if row["decision"] in {"MANUAL", "NOT_APPLICABLE"} and row["new_checks"]:
                    raise ValueError("Manual/out-of-scope decision contains an automatable proposal")
                pending = []
                for spec in row["new_checks"]:
                    require_fields(spec, {"id", "provider", "resource_kind", "data_source", "predicate", "severity", "category", "title", "description", "remediation_hint"}, "new check")
                    cid = spec["id"]
                    if spec["provider"] != source["provider"] or not isinstance(cid, str) or not cid:
                        raise ValueError("New check provider or ID mismatch")
                    if cid in proposed and proposed[cid] != spec:
                        raise ValueError("Conflicting proposed check specifications")
                    proposed[cid] = spec
                    # A reviewed new_checks entry is the signed association
                    # with this requirement. native_checks contains only the
                    # previously accepted native predicates.
                    survivor = reviewed_equivalent_proposal(spec, framework_id, rid, native)
                    if survivor is not None:
                        equivalent_seen.add((framework_id, rid, cid))
                        if survivor not in implemented_ids:
                            implemented_ids.append(survivor)
                    elif cid not in native:
                        pending.append(cid)
                    elif cid not in implemented_ids:
                        implemented_ids.append(cid)
                if any(native[cid].get("provider") not in {source["provider"], "all"} for cid in implemented_ids):
                    raise ValueError("Mapped native check provider differs from framework provider")
                if row["decision"] == "NEW_CHECK" and not row["new_checks"]:
                    raise ValueError("NEW_CHECK decision lacks a concrete predicate")
                if row["decision"] == "PARTIAL":
                    runtime_status = "partial" if implemented_ids else "not_assessed"
                elif row["decision"] == "MANUAL":
                    runtime_status = "manual"
                elif row["decision"] == "NOT_APPLICABLE":
                    runtime_status = "not_applicable"
                elif pending or not implemented_ids:
                    runtime_status = "not_assessed"
                else:
                    runtime_status = "automated"
                record = {"requirement_id": rid, "name": row["name"], "decision": row["decision"],
                          "runtime_status": runtime_status, "native_checks": sorted(implemented_ids),
                          "declared_check_ids": sorted(set(ids) | proposed_ids), "pending_checks": sorted(pending),
                          "removed_checks": row["removed_checks"], "reason": row["reason"], "evidence": row["evidence"]}
                compiled.append(record)
                for cid in implemented_ids:
                    by_check[cid].append({"framework_id": framework_id, "requirement_id": rid,
                                          "decision": row["decision"], "runtime_status": runtime_status})
            count += len(compiled)
            frameworks[framework_id] = {"id": framework_id, "name": source["name"], "provider": source["provider"],
                                        "requirements_total": len(compiled), "requirements": sorted(compiled, key=lambda value: value["requirement_id"])}
            if {item["requirement_id"] for item in compiled} != {item["id"] for item in matrix[framework_id]["requirements"]}:
                raise ValueError("Ledger decisions differ from pinned matrix requirements")
        if count != entry.get("requirements_total"):
            raise ValueError("Ledger requirement count differs from manifest")
    # Fixture ledgers may contain none of the two production-only duplicates.
    # When either signed proposal is present, demand its *whole* exact row set;
    # the canonical production ledger must retain both even if one is removed.
    canonical = ledger_root.resolve() == (Path(__file__).resolve().parent.parent / "docs/compliance-ledgers").resolve()
    expected_equivalents = set()
    if canonical or REVIEWED_EQUIVALENT_PROPOSAL["id"] in proposed:
        expected_equivalents.add((REVIEWED_EQUIVALENT_PROPOSAL["framework_id"],
                                  REVIEWED_EQUIVALENT_PROPOSAL["requirement_id"],
                                  REVIEWED_EQUIVALENT_PROPOSAL["id"]))
    if canonical or REVIEWED_CLOUDTRAIL_EQUIVALENT["id"] in proposed:
        expected_equivalents.update((framework_id, requirement_id, REVIEWED_CLOUDTRAIL_EQUIVALENT["id"])
                                    for framework_id, requirement_id in REVIEWED_CLOUDTRAIL_EQUIVALENT["rows"])
    from peaso.finding_priority import source_priority
    expected_rds = REVIEWED_RDS_CLUSTER_EQUIVALENT
    if expected_rds["survivor"] in native and (canonical or expected_rds["id"] in proposed):
        _reviewed_rds_signed_specs(proposed)
        expected_equivalents.update((framework_id, requirement_id, expected_rds["id"])
                                    for framework_id, requirement_id in expected_rds["rows"])
    if equivalent_seen != expected_equivalents:
        raise ValueError("Reviewed equivalent proposal missing or moved")
    if set(frameworks) != set(matrix):
        raise ValueError("Manifest does not cover every pinned framework")

    descriptions = {}
    for chunk, entry in sorted(manifest["descriptions"].items()):
        if entry.get("path") != "descriptions/" + chunk + ".json":
            raise ValueError("Description path does not match manifest chunk")
        data, _ = verified_file(ledger_root, entry, prefix="descriptions/")
        frozen_path = checked_path(ledger_root, "inputs/" + chunk + ".json", prefix="inputs/")
        ids = read_json(frozen_path)
        if digest(frozen_path.read_bytes()) != entry.get("input_sha256") or not isinstance(ids, list) or set(data) != set(ids) or len(ids) != entry.get("checks"):
            raise ValueError("Description chunk differs from frozen check-index slice")
        if set(descriptions) & set(data):
            raise ValueError("Duplicate check description across chunks")
        descriptions.update(data)
    if set(descriptions) != set(indexed):
        raise ValueError("Missing or overridden frozen check descriptions")
    if new_native:
        if supplement_entry is None or not new_native <= set(proposed):
            raise ValueError("New registered checks lack signed proposal descriptions")
    if supplement_entry is not None:
        supplemental, _ = verified_file(ledger_root, supplement_entry, prefix="descriptions/")
        if not isinstance(supplemental, dict) or set(supplemental) != new_native or len(supplemental) != supplement_entry.get("checks"):
            raise ValueError("Supplemental descriptions must match newly registered proposed IDs exactly")
        for cid, value in supplemental.items():
            require_fields(value, DESCRIPTION_FIELDS | {"proposed_spec_sha256"}, "supplement " + cid)
            if value["proposed_spec_sha256"] != spec_digest(proposed[cid]) or native[cid].get("provider") != proposed[cid]["provider"]:
                raise ValueError("Supplemental description does not match its verified proposed check")
            descriptions[cid] = {field: value[field] for field in DESCRIPTION_FIELD_ORDER}
    if set(descriptions) != set(indexed) | new_native:
        raise ValueError("Incomplete reviewed check descriptions")
    seen = {}
    allowlist = manifest.get("duplicate_description_allowlist", {})
    if not isinstance(allowlist, dict):
        raise ValueError("Malformed duplicate-description allowlist")
    for cid, value in descriptions.items():
        require_fields(value, DESCRIPTION_FIELDS, "description " + cid)
        title = str((indexed.get(cid) or native[cid]).get("title", ""))
        prose = value["description"]
        if not isinstance(prose, str) or len(prose.strip()) < 60 or prose.strip().casefold() == title.strip().casefold() or "inspect collected configuration without inferring effective access" in prose.casefold():
            raise ValueError("Empty, copied, or boilerplate description: " + cid)
        if not isinstance(value["evaluated"], list) or not value["evaluated"] or not all(isinstance(field, str) and field.strip() for field in value["evaluated"]):
            raise ValueError("Description lacks evaluated fields: " + cid)
        for field in ("pass_when", "fail_when"):
            if not isinstance(value[field], str) or len(value[field].strip()) < 15:
                raise ValueError("Description lacks " + field + ": " + cid)
        if value["not_applicable_when"] is not None and not isinstance(value["not_applicable_when"], str):
            raise ValueError("Malformed not-applicable text")
        duplicate = seen.get(prose)
        if duplicate:
            exception = allowlist.get(duplicate)
            if (not isinstance(exception, dict) or not isinstance(exception.get("reason"), str) or
                    len(exception["reason"].strip()) < 15 or cid not in exception.get("allowed_ids", [])):
                raise ValueError("Unreviewed duplicate description: " + duplicate + ", " + cid)
        seen.setdefault(prose, cid)
    for cid, spec in proposed.items():
        if cid in native and cid not in descriptions:
            raise ValueError("Implemented new check lacks a reviewed description: " + cid)

    reverse = {cid: sorted(tags, key=lambda tag: (tag["framework_id"], tag["requirement_id"])) for cid, tags in by_check.items()}
    forward = {(fid, row["requirement_id"], cid) for fid, fw in frameworks.items() for row in fw["requirements"] for cid in row["native_checks"]}
    backward = {(tag["framework_id"], tag["requirement_id"], cid) for cid, tags in reverse.items() for tag in tags}
    if forward != backward:
        raise ValueError("Requirement/check mapping is not bidirectional")
    counts = Counter(row["runtime_status"] for fw in frameworks.values() for row in fw["requirements"])
    requirements_pack = {"schema_version": 1, "source_manifest_sha256": digest(manifest_path.read_bytes()),
                         "frameworks": [frameworks[fid] for fid in sorted(frameworks)], "by_check": reverse,
                         "proposed_checks": [proposed[cid] for cid in sorted(proposed)], "counts": dict(sorted(counts.items())),
                         "hacktricks_best_practices": thematic}
    description_pack = {"schema_version": 1, "source_manifest_sha256": digest(manifest_path.read_bytes()), "checks": descriptions}
    return requirements_pack, description_pack


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger-root", type=Path, required=True)
    parser.add_argument("--audit-matrix", type=Path, required=True)
    parser.add_argument("--audit-summary", type=Path, required=True)
    parser.add_argument("--native-catalog", type=Path, required=True)
    parser.add_argument("--requirements-output", type=Path, required=True)
    parser.add_argument("--lookup-output", type=Path,
                        help="Compact lookup path; defaults beside requirements-output")
    parser.add_argument("--descriptions-output", type=Path, required=True)
    parser.add_argument("--coverage-output", type=Path)
    args = parser.parse_args()
    summary = read_json(args.audit_summary)
    if digest(args.audit_matrix.read_bytes()) != summary.get("detail_sha256"):
        raise ValueError("Pinned audit matrix hash does not match its summary")
    matrix = matrix_from(args.audit_matrix)
    native = read_json(args.native_catalog)
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from peaso.checks import CHECKS
    native = catalog_with_registered_checks(native, CHECKS)
    requirements, descriptions = compile_verified(args.ledger_root, matrix, native)
    requirements_bytes = (json.dumps(requirements, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    lookup = lookup_index(requirements, digest(requirements_bytes))
    lookup_path = args.lookup_output or args.requirements_output.with_name("compliance_lookup.json")
    args.requirements_output.parent.mkdir(parents=True, exist_ok=True)
    args.requirements_output.write_bytes(requirements_bytes)
    for path, value in ((args.descriptions_output, descriptions), (lookup_path, lookup)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n")
    if args.coverage_output:
        args.coverage_output.parent.mkdir(parents=True, exist_ok=True)
        args.coverage_output.write_text(json.dumps(coverage_matrix(matrix, requirements), indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"frameworks": len(requirements["frameworks"]), "requirements": sum(requirements["counts"].values()),
                      "descriptions": len(descriptions["checks"]), "states": requirements["counts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
