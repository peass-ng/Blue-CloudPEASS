"""Materialize catalog views from one verified compliance pack and live registry.

The upstream reference manifest remains a separate provenance input. This
script never rebuilds it or turns a reference mapping into a requirement pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PACK = ROOT / "peaso/rulepacks"
FRONTEND = ROOT / "frontend/src/frameworkCatalog.json"
LEDGER = ROOT / "docs/compliance-ledgers"


def render_documents() -> dict[Path, bytes]:
    from peaso.analysis import ANALYSIS_CHECKS
    from peaso.checks import CHECKS
    from peaso.checks.catalog import (_compliance, clear_caches, framework_catalog,
                                      full_requirements, manifest, proposal_provenance_for, runtime_metadata)
    from peaso.collectors import supported_types
    from peaso.server.catalog_view import frameworks_view
    from scripts.peaso_compliance_compile import lookup_index

    clear_caches()
    packed = _compliance()
    if packed is None:
        raise ValueError("Verified compliance packs are missing")
    requirements, descriptions = packed
    from peaso.checks.ecs_uid_description_overlay import validate_rows as validate_ecs_description_rows
    validate_ecs_description_rows(descriptions["checks"])
    from peaso.checks.aws_launch_ip_description_overlay import validate_rows as validate_launch_ip_rows
    validate_launch_ip_rows(descriptions["checks"])
    canonical = full_requirements()
    if lookup_index(canonical, requirements["full_pack_sha256"]) != requirements:
        raise ValueError("Compact lookup differs from canonical signed requirement pack")
    signed = hashlib.sha256((LEDGER / "manifest.json").read_bytes()).hexdigest()
    if requirements["source_manifest_sha256"] != signed or descriptions["source_manifest_sha256"] != signed:
        raise ValueError("Compiled packs do not match the current supervisor manifest")
    native_ids = {check.id for check in CHECKS}
    if len(native_ids) != len(CHECKS):
        raise ValueError("Duplicate registered native check")
    indexed = {row["id"] for row in json.loads((LEDGER / "inputs/check-index.json").read_text())}
    analysis_ids = {row["id"] for row in ANALYSIS_CHECKS}
    if set(descriptions["checks"]) != native_ids | analysis_ids:
        raise ValueError("Every registered check needs exactly one reviewed description")
    new_ids = native_ids - indexed
    if not new_ids <= set(requirements["by_check"]):
        raise ValueError("New registered checks lack reviewed requirement/control tags")
    for check in CHECKS:
        if check.id not in new_ids:
            continue
        signed_spec = proposal_provenance_for(check.id)
        if (signed_spec is None or check.provider != signed_spec["signed_provider"] or
                check.severity != signed_spec["signed_severity"]):
            raise ValueError("New check provider or severity differs from signed proposal: " + check.id)
        collected = set(supported_types(check.provider))
        if check.kind not in collected or any(kind not in collected for kind in check.dependencies):
            from peaso.checks.bulk_pending import MANIFEST as bulk_manifest
            from peaso.collectors.bulk_evidence import declared_types
            declared = collected | declared_types(check.provider)
            if check.id not in bulk_manifest['checks'] or not set(check.dependencies+[check.kind]) <= declared:
                raise ValueError("New check kind or dependency is not collected: " + check.id)
    for cid, tags in requirements["by_check"].items():
        if cid not in native_ids | analysis_ids or not tags:
            raise ValueError("Requirement map contains an absent or untagged check")

    source = manifest()
    runtime = runtime_metadata(source)
    runtime["compliance"] = {"schema_version": requirements["schema_version"],
                             "source_manifest_sha256": signed,
                             "requirements_total": sum(requirements["counts"].values())}
    framework_rows = framework_catalog()
    from peaso.checks.native_only import automated_checks, scope as automation_scope, exclusions
    active = automated_checks(CHECKS)
    from peaso.checks import azure_vm_ssh_source_correction, gcp_cloudsql_lockout_source_correction
    source_corrections = {module.CHECK_ID: {"spec": module.CORRECTED_SPEC,
                                          "provenance": module.correction_provenance()}
                          for module in (azure_vm_ssh_source_correction, gcp_cloudsql_lockout_source_correction)}
    from peaso.checks.aws_policy_source_correction import CORRECTIONS
    source_corrections.update({cid: {"spec": row["spec"], "provenance": row["provenance"]}
                               for cid, row in CORRECTIONS.items()})
    from peaso.checks import aws_ecr_source_correction as ecr_correction
    prior_ecr = next((row for row in canonical['proposed_checks']
                      if row['id'] == ecr_correction.CHECK_ID), None)
    if prior_ecr is None:
        raise ValueError('Historical ECR Public proposal missing')
    ecr_correction.validate_prior_spec(prior_ecr)
    source_corrections[ecr_correction.CHECK_ID] = {
        "spec": ecr_correction.CORRECTED_SPEC,
        "provenance": ecr_correction.correction_provenance(),
    }
    from peaso.checks import aws_pci_iam_scoped_source_correction as scoped_iam_correction
    prior_scoped_iam = next((row for row in canonical['proposed_checks']
                             if row['id'] == scoped_iam_correction.CHECK_ID), None)
    if prior_scoped_iam is None:
        raise ValueError('Historical scoped IAM customer-policy proposal missing')
    scoped_iam_correction.validate_prior_spec(prior_scoped_iam)
    source_corrections[scoped_iam_correction.CHECK_ID] = {
        "spec": scoped_iam_correction.CORRECTED_SPEC,
        "provenance": scoped_iam_correction.correction_provenance(),
    }
    public = [check.public() for check in active]
    if {check["id"] for check in public} != {check.id for check in active}:
        raise ValueError("Public native catalog differs from the registry")
    for check in public:
        if check["framework_ids"] != sorted({tag["framework_id"] for tag in check["requirement_controls"]}):
            raise ValueError("Public check framework IDs differ from reviewed control tags: " + check["id"])
    from peaso.collectors.bulk_evidence import coverage as evidence_coverage
    inventory_coverage = evidence_coverage()
    has_evidence_gaps = any(row['unavailable_projections'] for row in inventory_coverage.values())
    summary = {**runtime["coverage"], "active_native_checks": len(active), "automation_scope": automation_scope(), "inventory_coverage": inventory_coverage,
               "phase": "expansion_in_progress" if runtime["coverage"]["upstream"]["pending"] or has_evidence_gaps else "review_complete"}
    frameworks_view.cache_clear()
    frontend = frameworks_view()
    fixture = {key: frontend[key] for key in ("schema_version", "providers", "frameworks", "framework_versions", "limitations")}
    in_scope = {"aws", "azure", "gcp", "k8s", "all"}
    fixture["framework_versions"] = [row for row in frontend["framework_versions"]
                                      if row["provider"] in in_scope]
    version_ids = {row["id"] for row in fixture["framework_versions"]}
    fixture["frameworks"] = [
        {**row, "framework_ids": [identifier for identifier in row.get("framework_ids", [])
                                  if identifier in version_ids]}
        for row in frontend["frameworks"]
        if not row.get("framework_ids") or version_ids.intersection(row["framework_ids"])
    ]
    fixture["limitations"] = ["demo findings are illustrative fixtures; they are not a tenant assessment or compliance claim.",
                              *frontend["limitations"]]
    fixture["source"] = "peaso.server.catalog_view.frameworks_view"
    fixture["compliance_source_manifest_sha256"] = signed

    def encoded(value, *, compact=False):
        return (json.dumps(value, ensure_ascii=False, separators=(",", ":") if compact else None,
                           indent=None if compact else 2) + "\n").encode()

    return {PACK / "runtime_metadata.json": encoded(runtime, compact=True),
            PACK / "native_catalog.json": encoded({"schema_version": "1.0", "evaluator_version": "1.0.0",
                                                    "compliance_source_manifest_sha256": signed, "automation_scope": automation_scope(), "checks": public,
                                                    "archived_checks": [check.public() for check in CHECKS if check.id in exclusions()],
                                                    "excluded_controls": exclusions(), "source_corrections": source_corrections}, compact=True),
            PACK / "framework_catalog.json": encoded({"schema_version": "1.0", "compliance_source_manifest_sha256": signed,
                                                       "frameworks": framework_rows}),
            PACK / "catalog_summary.json": encoded(summary),
            FRONTEND: encoded(fixture, compact=True)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Write the five reviewed views after all checks pass")
    args = parser.parse_args(argv)
    outputs = render_documents()
    stale = [path for path, payload in outputs.items() if not path.is_file() or path.read_bytes() != payload]
    if args.write:
        for path, payload in outputs.items():
            path.write_bytes(payload)
        print(json.dumps({"written": [str(path.relative_to(ROOT)) for path in stale], "checked": len(outputs)}))
        return 0
    print(json.dumps({"stale": [str(path.relative_to(ROOT)) for path in stale], "checked": len(outputs)}))
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
