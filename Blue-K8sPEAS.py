#!/usr/bin/env python3
"""Audit Kubernetes RBAC grants and service-account exposure."""

from __future__ import annotations

import argparse
import json
import sys

from bluepeass.k8s import analyze_snapshot, fetch_snapshot, read_audit_log
from bluepeass.normalize import normalize_k8s_cluster
from bluepeass.report import Target, atomic_write_json, build_report


def _print_section(label: str, values: list, max_items: int, formatter) -> None:
    print(f"{label}: {len(values)}")
    for item in values[:max_items]:
        print(f"  - {formatter(item)}")
    if len(values) > max_items:
        print(f"  ... {len(values) - max_items} more in --out-json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Kubernetes RBAC and service-account audit")
    parser.add_argument("--context", help="kubectl context to scan (default: current context)")
    parser.add_argument("--kubectl", default="kubectl", help="kubectl executable (default: kubectl)")
    parser.add_argument("--input-json", help="Analyze a previously captured snapshot instead of contacting a cluster")
    parser.add_argument("--audit-log", help="Optional Kubernetes JSON-lines audit log for observed activity")
    parser.add_argument("--min-unused-days", type=int, default=90, help="Audit activity lookback and token inactivity threshold in days (default: 90)")
    parser.add_argument("--out-json", help="Write the normalized JSON report to this file")
    parser.add_argument("--risk-levels", default="high,critical", help="Comma-separated levels to flag: low,medium,high,critical")
    parser.add_argument("--max-items", type=int, default=20, help="Maximum findings to print per section")
    args = parser.parse_args(argv)
    levels = {level.strip() for level in args.risk_levels.lower().split(",")}
    if not levels or not levels <= {"low", "medium", "high", "critical"}:
        parser.error("--risk-levels must contain only low,medium,high,critical")
    if args.max_items < 0:
        parser.error("--max-items must be nonnegative")
    if args.min_unused_days < 1:
        parser.error("--min-unused-days must be positive")

    try:
        if args.input_json:
            with open(args.input_json, encoding="utf-8") as stream:
                snapshot = json.load(stream)
            if not isinstance(snapshot, dict):
                raise ValueError("snapshot must be a JSON object")
        else:
            snapshot = fetch_snapshot(args.kubectl, args.context)
        result = analyze_snapshot(snapshot, levels, audit_events=read_audit_log(args.audit_log) if args.audit_log else None, min_unused_days=args.min_unused_days)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    findings = result["findings"]
    print(f"Blue K8sPEASS — context: {result['context'] or '<unknown>'}")
    print("Inventory: " + ", ".join(f"{kind}={count}" for kind, count in result["inventory"].items()))
    _print_section("Principals with flagged RBAC grants", findings["principals_flagged"], args.max_items,
                   lambda p: f"{p['principal']} @ {p['scope']}: " + ", ".join(f"{level}={len(perms)}" for level, perms in p["flagged_permissions"].items()))
    for principal in findings["principals_flagged"][:args.max_items]:
        flagged_permissions = [permission for permission in principal["permissions"] if permission["risk"] in levels]
        for permission in flagged_permissions[:args.max_items]:
            print(f"      {permission['risk']}: {permission['permission']}")
            for source in permission["sources"][:args.max_items]:
                via = f" via {source['via_group']}" if source.get("via_group") else ""
                print(f"        from {source['role']} ({source['binding']}){via}")
        if len(flagged_permissions) > args.max_items:
            print(f"      ... {len(flagged_permissions) - args.max_items} more permissions in --out-json")
    _print_section("Unbound role definitions", findings["unused_custom_definitions"], args.max_items,
                   lambda r: f"{r['kind']}/{r['scope']}/{r['name']}")
    _print_section("Service accounts without listed workloads", findings["service_accounts_without_workloads"], args.max_items, str)
    _print_section("Long-lived service-account token Secrets", findings["token_secrets"], args.max_items,
                   lambda s: f"{s['namespace']}/{s['name']} -> {s['service_account'] or '<unknown>'}")
    _print_section("Legacy token Secrets inactive for the threshold", findings["inactive_token_secrets"], args.max_items,
                   lambda s: f"{s['namespace']}/{s['name']}: last used {s['last_used']} ({s['days_since_last_use']} days ago)")
    _print_section("Invalidated legacy token Secrets", findings["invalid_token_secrets"], args.max_items,
                   lambda s: f"{s['namespace']}/{s['name']}: invalid since {s['invalid_since']}")
    _print_section("Broad or public RBAC bindings", findings["external_trusts"], args.max_items,
                   lambda b: f"{b['subject']} -> {b['role']} @ {b['scope']} ({b['binding']})")
    _print_section("Cloud workload identity annotations", findings["workload_identity_trusts"], args.max_items,
                   lambda t: f"{t['service_account']}: {t['annotation']}={t['target']}")
    _print_section("Workloads using flagged service accounts", findings["workloads_with_flagged_service_accounts"], args.max_items,
                   lambda w: f"{w['kind']}/{w['namespace']}/{w['name']} -> {w['service_account']} ({len(w['flagged_permissions'])} flagged grants)")
    _print_section("Workload creation paths to flagged service accounts", findings["workload_creation_paths_to_flagged_service_accounts"], args.max_items,
                   lambda path: f"{path['principal']} @ {path['grant_scope']} can create {','.join(path['workload_resources'])} in {path['namespace']} using {path['service_account']} ({len(path['service_account_flagged_permissions'])} flagged grants)")
    _print_section("Dangling role references", findings["dangling_bindings"], args.max_items,
                   lambda b: f"{b['binding']} -> {b['role']}")
    if args.audit_log:
        _print_section("Principals not observed in supplied audit events", findings["principals_not_observed"], args.max_items,
                       lambda p: f"{p['principal']} @ {p['scope']}")
        _print_section("Grants not observed in supplied audit events", findings["permissions_not_observed"], args.max_items,
                       lambda p: f"{p['principal']} @ {p['scope']}: {len(p['permissions'])} permissions")
    if result["coverage"]["missing"]:
        print("Missing reads: " + ", ".join(result["coverage"]["missing"]))
    if result["errors"]:
        print(f"Read errors: {len(result['errors'])} (details in --out-json)")
    if args.audit_log:
        print("Unused individual permissions: unverified; audit results show only what was observed in the supplied log.")
    else:
        print("Unused individual permissions: unavailable without audit activity data.")

    if args.out_json:
        report = build_report(
            provider="k8s",
            targets=[Target(target_type="cluster", target_id=str(result["context"] or "unknown"), label=result["context"], data=normalize_k8s_cluster(result)).to_dict()],
            extra_summary={"principals_flagged": len(findings["principals_flagged"]), "coverage_complete": not result["coverage"]["missing"] and result["coverage"]["api_discovery_available"] and not result["errors"]},
        )
        try:
            atomic_write_json(args.out_json, report)
        except OSError as exc:
            print(f"Error writing JSON report: {exc}", file=sys.stderr)
            return 2
        print(f"JSON report: {args.out_json}")
    # RBAC is the core of this audit. Missing it is a partial scan, not success.
    return 1 if any(kind not in snapshot.get("resources", {}) for kind in ("roles", "clusterroles", "rolebindings", "clusterrolebindings")) else 0


if __name__ == "__main__":
    raise SystemExit(main())
