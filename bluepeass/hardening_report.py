"""Group hardening results across targets and render the same model as Markdown."""

from __future__ import annotations

import collections
import copy
import hashlib
import html
import json
from pathlib import Path
import re
from urllib.parse import quote, urlsplit


ACTION_STATUSES = {"FAIL", "MANUAL", "ERROR"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "unknown": 5}


def _serialized(value):
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _provider(value):
    return "kubernetes" if value == "k8s" else value


def _service(definition, provider):
    service = definition.get("service") or (definition.get("tags") or {}).get("service")
    return str(service) if service else provider.upper() + "/Other"


def group_hardening_targets(targets, provider):
    """One service/check definition with all asset observations across accounts.

    A resource ID is scoped by provider and target. Different regional/status
    observations and different audit identities remain distinct under that asset.
    The input is never changed: callers may still need its native rows.
    """
    groups, scoped_targets, errors = {}, [], []
    scan_occurrences = collections.Counter()
    states, versions = collections.Counter(), collections.defaultdict(set)
    all_assets, affected_assets = set(), set()
    by_status = collections.Counter()
    controls_attempted = 0

    def finding_group(definition, scope_provider):
        control_id = str(definition.get("control_id") or "unknown")
        key = (scope_provider, control_id)
        if key not in groups:
            groups[key] = {
                "finding_id": scope_provider + ":" + control_id,
                "provider": scope_provider,
                "service": _service(definition, scope_provider),
                "control_id": control_id,
                "title": definition.get("title") or control_id,
                "description": definition.get("description") or "",
                "severity": definition.get("severity") or "unknown",
                "tags": copy.deepcopy(definition.get("tags") or {}),
                "suites": set(), "reference_urls": set(), "assets": {}, "error_ids": [],
            }
        group = groups[key]
        for suite in definition.get("suites", []):
            group["suites"].add(suite)
        if definition.get("suite"):
            group["suites"].add(definition["suite"])
        if definition.get("reference_url"):
            group["reference_urls"].add(definition["reference_url"])
        return group

    for target in targets:
        audit = (target.get("data") or {}).get("hardening")
        if not isinstance(audit, dict):
            continue
        target_id = str(target.get("target_id", "unknown"))
        identity = (_provider(provider), target.get("target_type", "scope"), target_id, target.get("label"))
        digest = hashlib.sha256(_serialized(identity).encode()).hexdigest()[:16]
        scan_occurrences[digest] += 1
        scan_id = "scan-" + digest + "-" + str(scan_occurrences[digest])
        scope = {
            "scan_id": scan_id, "target_id": target_id,
            "target_type": target.get("target_type", "scope"), "label": target.get("label"),
            "status": audit.get("status", "unknown"),
            "coverage": copy.deepcopy(audit.get("coverage", {})),
            "summary": copy.deepcopy(audit.get("summary", {})),
            "controls": [{key: control[key] for key in ("control_id", "suite", "rows") if key in control} for control in audit.get("controls", [])],
            "finding_ids": set(), "error_ids": [],
        }
        for name in ("reason", "exports_directory"):
            if name in audit:
                scope[name] = audit[name]
        scoped_targets.append(scope)
        states[scope["status"]] += 1
        controls_attempted += len(scope["controls"])
        for name, version in audit.get("versions", {}).items():
            versions[name].add(version)
        definitions = {control["control_id"]: control for control in audit.get("controls", [])}
        scope_provider = _provider(provider)

        for row in audit.get("findings", []):
            row_provider = _provider(row.get("provider") or scope_provider)
            group = finding_group(row, row_provider)
            scope["finding_ids"].add(group["finding_id"])
            resource = row.get("resource")
            asset_key = (row_provider, target_id, _serialized(resource))
            asset = group["assets"].setdefault(asset_key, {
                "provider": row_provider, "target_id": target_id, "resource": resource,
                "observations": {},
            })
            observation = {
                "scan_id": scan_id, "status": row.get("status", "UNKNOWN"),
                "reason": row.get("reason", ""), "dimensions": copy.deepcopy(row.get("dimensions") or {}),
                "suites": sorted(set(row.get("suites", []))),
            }
            observation_key = _serialized({k: v for k, v in observation.items() if k != "suites"})
            if observation_key in asset["observations"]:
                existing = asset["observations"][observation_key]
                existing["suites"] = sorted(set(existing["suites"]) | set(observation["suites"]))
            else:
                asset["observations"][observation_key] = observation
                by_status[observation["status"]] += 1
            all_assets.add(asset_key)
            if observation["status"] in ACTION_STATUSES:
                affected_assets.add(asset_key)

        for error in audit.get("errors", []):
            error_id = "error-" + str(len(errors) + 1)
            scoped_error = {**copy.deepcopy(error), "error_id": error_id, "scan_id": scan_id, "target_id": target_id}
            errors.append(scoped_error)
            scope["error_ids"].append(error_id)
            if error.get("control_id"):
                definition = definitions.get(error["control_id"], {"control_id": error["control_id"]})
                group = finding_group(definition, scope_provider)
                group["error_ids"].append(error_id)
                scope["finding_ids"].add(group["finding_id"])

    if not scoped_targets:
        return None

    services = {}
    affected_findings = 0
    for group in groups.values():
        assets = []
        group_counts = collections.Counter()
        affected = 0
        for _, asset in sorted(group["assets"].items(), key=lambda item: item[0]):
            asset["observations"] = sorted(asset["observations"].values(), key=_serialized)
            asset["affected"] = any(o["status"] in ACTION_STATUSES for o in asset["observations"])
            affected += int(asset["affected"])
            group_counts.update(o["status"] for o in asset["observations"])
            assets.append(asset)
        group["assets"] = assets
        group["suites"] = sorted(group["suites"])
        group["reference_urls"] = sorted(group["reference_urls"])
        group["summary"] = {"assets": len(assets), "affected_assets": affected,
                            "resource_evaluations": sum(group_counts.values()), "by_status": dict(sorted(group_counts.items()))}
        if affected or group["error_ids"]:
            affected_findings += 1
        key = (group["provider"], group["service"])
        services.setdefault(key, {"provider": group["provider"], "service": group["service"], "findings": []})["findings"].append(group)
    ordered_services = []
    for key in sorted(services):
        service = services[key]
        service["findings"].sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"].lower(), 5), f["title"].casefold(), f["control_id"]))
        ordered_services.append(service)
    for scope in scoped_targets:
        scope["finding_ids"] = sorted(scope["finding_ids"])
    complete = all(scope["coverage"].get("complete", False) for scope in scoped_targets)
    status = "completed" if complete else "partial"
    if len(states) == 1 and next(iter(states)) in {"disabled", "skipped", "unavailable", "error"}:
        status = next(iter(states))
    return {
        "schema_version": 2, "engine": "steampipe-powerpipe", "status": status,
        "services": ordered_services, "targets": scoped_targets, "errors": errors,
        "versions": {name: sorted(values) for name, values in sorted(versions.items())},
        "summary": {"targets": len(scoped_targets), "states": dict(sorted(states.items())),
                    "services": len(ordered_services), "findings": len(groups), "affected_findings": affected_findings,
                    "assets": len(all_assets), "affected_assets": len(affected_assets),
                    "resource_evaluations": sum(by_status.values()), "by_status": dict(sorted(by_status.items())),
                    "controls": controls_attempted, "execution_errors": len(errors), "coverage_complete": complete},
    }


def _md(value):
    text = html.escape(str(value if value is not None else ""), quote=False)
    text = re.sub(r"([\\`*_{}\[\]()#+!|])", r"\\\1", text)
    return "<br>".join(text.splitlines())


def _link(url):
    try:
        scheme = urlsplit(str(url)).scheme
    except ValueError:
        return None
    if scheme not in {"http", "https"}:
        return None
    return quote(str(url), safe="/:?=&%#@+;,")


def render_hardening_markdown(report, *, show_passed=False):
    """Render each check once with a compact table of all scoped assets."""
    if not report:
        return ""
    summary = report["summary"]
    lines = ["## Infrastructure hardening", "",
             f"**Coverage:** {_md(report['status'])} · **Targets:** {summary['targets']} · **Affected findings:** {summary['affected_findings']} · **Affected assets:** {summary['affected_assets']}", ""]
    if summary["by_status"]:
        lines += ["**Resource evaluations:** " + ", ".join(f"{_md(status)}={count}" for status, count in summary["by_status"].items()), ""]
    scopes = {scope["scan_id"]: scope for scope in report["targets"]}
    errors = {error["error_id"]: error for error in report["errors"]}
    associated_errors = set()
    for service in report["services"]:
        selected = [finding for finding in service["findings"] if finding["error_ids"] or any(
            show_passed or observation["status"] in ACTION_STATUSES
            for asset in finding["assets"] for observation in asset["observations"])]
        if not selected:
            continue
        lines += ["### " + _md(service["service"]), ""]
        for finding in selected:
            lines += ["#### " + _md(finding["title"]), "", "**Control:** " + _md(finding["control_id"]), ""]
            if finding["severity"] != "unknown":
                lines += ["**Severity:** " + _md(finding["severity"]), ""]
            if finding["description"]:
                lines += [_md(finding["description"]), ""]
            references = [url for reference in finding["reference_urls"] if (url := _link(reference))]
            if references:
                lines += [" · ".join(f"[Control reference {i}]({url})" for i, url in enumerate(references, 1)), ""]
            rows = []
            for asset in finding["assets"]:
                for observation in asset["observations"]:
                    if not show_passed and observation["status"] not in ACTION_STATUSES:
                        continue
                    scope = scopes[observation["scan_id"]]
                    target = asset["target_id"]
                    if scope.get("label") and scope["label"] != target:
                        target += " (" + scope["label"] + ")"
                    dimensions = ", ".join(f"{key}={value}" for key, value in sorted(observation["dimensions"].items()) if value not in (None, ""))
                    rows.append("| " + " | ".join(_md(v) for v in [target, asset["resource"], dimensions, observation["status"], observation["reason"]]) + " |")
            if rows:
                lines += [f"**Affected assets:** {finding['summary']['affected_assets']}", "",
                          "| Target | Resource | Scope | Status | Evidence |", "| --- | --- | --- | --- | --- |", *rows, ""]
            if finding["error_ids"]:
                lines += ["**Checks that could not complete:**", "", "| Target | Error |", "| --- | --- |"]
                for error_id in finding["error_ids"]:
                    error = errors[error_id]
                    lines.append(f"| {_md(error['target_id'])} | {_md(error.get('error', 'Unknown error'))} |")
                    associated_errors.add(error_id)
                lines.append("")
    lines += ["### Coverage by target", "", "| Target | State | Notes |", "| --- | --- | --- |"]
    for scope in report["targets"]:
        notes = []
        if scope.get("reason"):
            notes.append(scope["reason"])
        coverage = scope["coverage"]
        empty = len(coverage.get("zero_result_controls", []))
        if empty:
            notes.append(f"{empty} controls returned no resource rows")
        if scope["error_ids"]:
            notes.append(f"{len(scope['error_ids'])} execution errors")
        for excluded in coverage.get("excluded_controls", []):
            notes.append(f"SKIP {excluded['control_id']}: {excluded['reason']}")
        for preflight in coverage.get("preflight", []):
            if not preflight.get("allowed"):
                notes.append(f"Preflight read unavailable: {preflight.get('read')} ({preflight.get('error', 'not granted')})")
        if scope.get("exports_directory"):
            notes.append("Native exports: " + scope["exports_directory"])
        lines.append("| " + " | ".join(_md(v) for v in [scope["target_id"], scope["status"], "\n".join(notes)]) + " |")
    unassociated = [e for e in report["errors"] if e["error_id"] not in associated_errors]
    if unassociated:
        lines += ["", "### Runner and suite errors", "", "| Target | Suite | Error |", "| --- | --- | --- |"]
        for error in unassociated:
            lines.append("| " + " | ".join(_md(v) for v in [error["target_id"], error.get("suite", error.get("mod", "runner")), error.get("error")]) + " |")
    return "\n".join(lines) + "\n"


def publish_hardening_report(args, targets, provider):
    report = group_hardening_targets(targets, provider)
    if report is None:
        return
    markdown = render_hardening_markdown(report, show_passed=args.hardening_show_passed)
    print("\n" + markdown, end="")
    destination = getattr(args, "hardening_out_markdown", None)
    if destination:
        path = Path(destination)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(markdown, encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)
