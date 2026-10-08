#!/usr/bin/env python3
"""Audit Kubernetes RBAC grants and service-account exposure."""

from __future__ import annotations

import argparse
import json
import sys

from bluepeass.k8s import analyze_snapshot, fetch_snapshot, read_audit_log, _new_api
from bluepeass.hardening import KubernetesCredentials, add_hardening_arguments, validate_hardening_arguments, run_hardening, print_hardening, attach_hardening
from bluepeass.normalize import normalize_k8s_cluster
from bluepeass.report import Target, atomic_write_json, build_report
from bluepeass.hardening_report import publish_hardening_report


def _print_section(label: str, values: list, max_items: int, formatter) -> None:
    print(f"{label}: {len(values)}")
    for item in values[:max_items]:
        print(f"  - {formatter(item)}")
    if len(values) > max_items:
        print(f"  ... {len(values) - max_items} more in --out-json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Kubernetes RBAC and service-account audit")
    add_hardening_arguments(parser)
    parser.add_argument("--context", help="Kubeconfig context to scan (default: current context)")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig (default: KUBECONFIG or ~/.kube/config)")
    parser.add_argument("--in-cluster", action="store_true", help="Use the pod's mounted service-account credentials")
    parser.add_argument("--server", help="Kubernetes API URL for direct bearer-token authentication")
    parser.add_argument("--token-file", help="File containing a bearer token for --server")
    parser.add_argument("--ca-cert", help="CA certificate for --server (defaults to system trust)")
    parser.add_argument("--input-json", help="Analyze a previously captured snapshot instead of contacting a cluster")
    parser.add_argument("--audit-log", help="Optional Kubernetes JSON-lines audit log for observed activity")
    parser.add_argument("--min-unused-days", type=int, default=90, help="Audit activity lookback in days (default: 90)")
    parser.add_argument("--out-json", help="Write the normalized JSON report to this file")
    parser.add_argument("--risk-levels", default="high,critical", help="Comma-separated levels to flag: low,medium,high,critical")
    parser.add_argument("--max-items", type=int, default=20, help="Maximum findings to print per section")
    args = parser.parse_args(argv)
    validate_hardening_arguments(parser, args)
    levels = {level.strip() for level in args.risk_levels.lower().split(",")}
    if not levels or not levels <= {"low", "medium", "high", "critical"}:
        parser.error("--risk-levels must contain only low,medium,high,critical")
    if args.max_items < 0:
        parser.error("--max-items must be nonnegative")
    if args.min_unused_days < 1:
        parser.error("--min-unused-days must be positive")
    if args.server and not args.token_file:
        parser.error("--server requires --token-file")
    if (args.token_file or args.ca_cert) and not args.server:
        parser.error("--token-file and --ca-cert require --server")
    if args.server and (args.context or args.kubeconfig or args.in_cluster):
        parser.error("--server cannot be combined with kubeconfig or in-cluster options")
    if args.in_cluster and (args.context or args.kubeconfig):
        parser.error("--in-cluster cannot be combined with kubeconfig options")

    api = None
    try:
        if args.input_json:
            with open(args.input_json, encoding="utf-8") as stream:
                snapshot = json.load(stream)
            if not isinstance(snapshot, dict):
                raise ValueError("snapshot must be a JSON object")
        else:
            api, label = _new_api(
                context=args.context, kubeconfig=args.kubeconfig,
                in_cluster=args.in_cluster, server=args.server,
                token_file=args.token_file, ca_cert=args.ca_cert,
            )
            snapshot = fetch_snapshot(api=api, context=label)
        result = analyze_snapshot(snapshot, levels, audit_events=read_audit_log(args.audit_log) if args.audit_log else None, min_unused_days=args.min_unused_days)
    except (OSError, ValueError, RuntimeError) as exc:
        if api is not None:
            api.close()
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    findings = result["findings"]
    print(f"Blue K8sPEASS — context: {result['context'] or '<unknown>'}")
    print("Inventory: " + ", ".join(f"{kind}={count}" for kind, count in result["inventory"].items()))
    print(f"Principals with flagged RBAC grants: {len(findings['principals_flagged'])}")
    for principal in findings["principals_flagged"][:args.max_items]:
        counts = ", ".join(f"{level}={len(perms)}" for level, perms in principal["flagged_permissions"].items())
        print(f"  - {principal['principal']} @ {principal['scope']}: {counts}")
        flagged_permissions = [permission for permission in principal["permissions"] if permission["risk"] in levels]
        for permission in flagged_permissions[:args.max_items]:
            print(f"      {permission['risk']}: {permission['permission']}")
            for source in permission["sources"][:args.max_items]:
                via = f" via {source['via_group']}" if source.get("via_group") else ""
                print(f"        from {source['role']} ({source['binding']}){via}")
        if len(flagged_permissions) > args.max_items:
            print(f"      ... {len(flagged_permissions) - args.max_items} more permissions in --out-json")
    if len(findings["principals_flagged"]) > args.max_items:
        print(f"  ... {len(findings['principals_flagged']) - args.max_items} more principals in --out-json")
    _print_section("Unbound role definitions", findings["unused_custom_definitions"], args.max_items,
                   lambda r: f"{r['kind']}/{r['scope']}/{r['name']}")
    _print_section("Service accounts without listed workloads", findings["service_accounts_without_workloads"], args.max_items, str)
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

    if api is not None:
        try:
            result["hardening"] = run_hardening(args, KubernetesCredentials(api), str(result["context"]))
        finally:
            api.close()
        publish_hardening_report(args, [Target(target_type="cluster", target_id=str(result["context"]), label=result["context"], data={"hardening": result["hardening"]}).to_dict()], "k8s")

    if args.out_json:
        report = build_report(
            provider="k8s",
            targets=[Target(target_type="cluster", target_id=str(result["context"] or "unknown"), label=result["context"], data=attach_hardening(normalize_k8s_cluster(result), result.get("hardening"))).to_dict()],
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
