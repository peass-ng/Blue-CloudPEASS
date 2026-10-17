"""Native snapshot hardening bridge for the existing IAM/RBAC scanner entrypoints.

Authentication remains bound to the selected scanner credentials. Configuration
is read once by native collectors; all checks evaluate those facts offline.
"""
from __future__ import annotations
import json
from collections import Counter
from pathlib import Path
import urllib.request
from bluepeass.hardening_report import group_hardening_targets, render_hardening_markdown


def add_hardening_arguments(parser):
    group = parser.add_argument_group("Native snapshot security review")
    group.add_argument("--hardening", choices=["auto", "on", "off"], default="auto", help="Run native snapshot security checks (auto/on), or keep only the IAM/RBAC audit (off).")
    group.add_argument("--hardening-out-dir", help="Retain native snapshot and report JSON per target.")
    group.add_argument("--hardening-show-passed", action="store_true", help="Also display passing native checks; JSON retains every status.")
    group.add_argument("--hardening-out-markdown", help="Write grouped native security results as Markdown.")


def validate_hardening_arguments(parser, args):
    return None


def _http(url, token, *, body=None, quota_project=None):
    """Existing read-only JSON transport shared by provider adapters."""
    headers = {"Authorization": "Bearer " + token}
    if quota_project:
        headers["X-Goog-User-Project"] = quota_project
    payload = json.dumps(body).encode() if body is not None else None
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, headers=headers, data=payload)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


class AwsCredentials:
    provider = "aws"
    def __init__(self, session):
        self.session = session


class GcpCredentials:
    provider = "gcp"
    def __init__(self, token, project, quota_project=None, token_supplier=None):
        self.token, self.project, self.quota_project = token, project, quota_project
        self.token_supplier = token_supplier


class AzureCredentials:
    provider = "azure"
    def __init__(self, credential, subscription, tenant=None):
        self.credential, self.subscription, self.tenant = credential, subscription, tenant


class KubernetesCredentials:
    provider = "k8s"
    def __init__(self, api):
        self.api = api


def _empty(status, reason):
    return {"engine": "peaso-native", "status": status, "reason": reason, "findings": [], "controls": [], "errors": [],
        "coverage": {"complete": False}, "summary": {"findings": 0, "controls": 0, "execution_errors": 0, "by_status": {}}}


def run_hardening(args, adapter, target):
    if args.hardening == "off":
        return _empty("disabled", "Native snapshot review disabled.")
    try:
        from peaso.engine import run_scan, evaluate_snapshot
        provider = adapter.provider
        connector = {"provider": provider, "name": str(target), "scopes": [str(target)], "auth": {}, "options": {}}
        if provider == "aws":
            credentials = adapter.session.get_credentials()
            if credentials is None:
                return _empty("unknown", "Selected AWS session has no credentials.")
            frozen = credentials.get_frozen_credentials()
            connector["auth"] = {"aws_access_key_id": frozen.access_key, "aws_secret_access_key": frozen.secret_key}
            if frozen.token:
                connector["auth"]["aws_session_token"] = frozen.token
        elif provider == "gcp":
            token = adapter.token_supplier() if adapter.token_supplier else adapter.token
            connector["scopes"] = [adapter.project]
            connector["auth"] = {"token": token, "quota_project": adapter.quota_project}
        elif provider == "azure":
            connector["scopes"] = [adapter.subscription]
            connector["auth"] = {"token": adapter.credential.get_token("https://management.azure.com/.default").token}
            if adapter.tenant:
                connector["auth"]["tenant_id"] = adapter.tenant
        if provider == "k8s":
            from peaso.collectors.k8s import collect
            connector["scopes"] = ["*"]
            snapshot = collect(connector, api=adapter.api)
            report = evaluate_snapshot(snapshot)
            report["snapshot"] = snapshot
        else:
            report = run_scan({"connector": connector, "embed_snapshot": bool(getattr(args, "hardening_out_dir", None))})
        findings = [{**finding, "control_id": finding["check_id"], "resource": finding["resource_id"],
            "reason": json.dumps(finding["evidence"], sort_keys=True), "dimensions": {"scope": finding["scope"], "service": finding["service"]},
            "suites": ["peaso-native"], "reference_urls": [], "description": finding["remediation"]} for finding in report["findings"]]
        finding_counts = Counter(f["check_id"] for f in findings)
        controls = [{"control_id": row["check_id"], "title": row["check_id"], "suite": "peaso-native", "rows": finding_counts[row["check_id"]]}
            for row in report["coverage"] if row["level"] == "check"]
        errors = [{"control_id": row.get("check_id", row.get("type")), "error": row.get("reason") or row["status"]}
            for row in report["coverage"] if row["status"] in ("denied", "unknown", "partial", "timeout", "not_collected", "malformed")]
        result = {"engine": "peaso-native", "status": "completed" if report["stats"]["coverage_complete"] else "partial",
            "findings": findings, "controls": controls, "errors": errors, "coverage": {"complete": report["stats"]["coverage_complete"], "native": report["coverage"]},
            "summary": {"findings": len(findings), "controls": len(controls), "execution_errors": len(errors), "by_status": dict(Counter(f["status"] for f in findings))},
            "snapshot_id": report["snapshot_id"], "versions": {"peaso-native": "0.1.0"}}
        if getattr(args, "hardening_out_dir", None):
            from peaso.cli import _write
            from peaso.snapshot import digest
            root = Path(args.hardening_out_dir) / digest([provider, str(target)]).split(":", 1)[1][:16]
            _write(report["snapshot"], root / "snapshot.json", "json")
            _write(report, root / "report.json", "json")
        return result
    except Exception as exc:
        result = _empty("unknown", "Native review unavailable: " + type(exc).__name__)
        result["errors"] = [{"error": result["reason"]}]
        return result


def print_hardening(result, *, target, show_passed=False):
    if not result:
        return
    provider = next((row.get("provider") for row in result.get("findings", []) if row.get("provider")), "unknown")
    grouped = result if "services" in result else group_hardening_targets([{"target_id": str(target), "data": {"hardening": result}}], provider)
    print("\n" + render_hardening_markdown(grouped, show_passed=show_passed), end="")


def attach_hardening(data, result):
    if result is not None:
        data["hardening"] = result
    return data
