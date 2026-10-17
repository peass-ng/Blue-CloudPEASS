#!/usr/bin/env python3
"""Verify a real hosted read-only API key without persisting its secret.

The key arrives on an inherited file descriptor, never argv or environment.
A separate signed-in browser flow creates it once and revokes it afterward.
Run only after an exact coordinator grant and matching release verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlparse

import httpx

HOST = "https://cspm.hacktricks.wiki"
SORTS = ("severity", "title", "service", "account", "status", "resource_id")
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
MAX_PAGE = 500
MAX_PAGES = 100
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


class ContractFailure(Exception):
    """No response data or secret-bearing URL is stored in this exception."""


def require(condition: bool, phase: str) -> None:
    if not condition:
        raise ContractFailure(phase)


def get_json(client: httpx.Client, path: str, phase: str, status: int = 200) -> dict:
    response = client.get(path)
    require(response.status_code == status, phase + ":status")
    if status != 200:
        return {}
    try:
        value = response.json()
    except ValueError:
        raise ContractFailure(phase + ":json") from None
    require(isinstance(value, dict), phase + ":shape")
    return value


def artifact(client: httpx.Client, value: dict, phase: str) -> dict:
    """Fetch private presigned material with a separate client and no API key."""
    require(isinstance(value.get("download_url"), str), phase + ":envelope")
    parsed = urlparse(value["download_url"])
    require(parsed.scheme == "https" and parsed.hostname is not None and
            parsed.hostname.endswith(".amazonaws.com"), phase + ":destination")
    size = 0
    digest = hashlib.sha256()
    first = b""
    with httpx.stream("GET", value["download_url"], timeout=120, follow_redirects=False) as response:
        require(response.status_code == 200, phase + ":download")
        for chunk in response.iter_bytes():
            size += len(chunk)
            require(size <= MAX_ARTIFACT_BYTES, phase + ":size")
            if len(first) < 16:
                first += chunk[:16 - len(first)]
            digest.update(chunk)
    require(size > 0, phase + ":empty")
    return {"bytes": size, "sha256": digest.hexdigest(), "first": first.lstrip()[:1]}


def page_all(client: httpx.Client, path: str, phase: str) -> tuple[list[dict], int]:
    rows: list[dict] = []
    total = None
    for _ in range(MAX_PAGES):
        separator = "&" if "?" in path else "?"
        page = get_json(client, f"{path}{separator}limit={MAX_PAGE}&offset={len(rows)}", phase)
        items = page.get("items")
        require(isinstance(items, list) and isinstance(page.get("total"), int), phase + ":page")
        if total is None:
            total = page["total"]
        require(page["total"] == total, phase + ":total-drift")
        rows.extend(items)
        require(len(rows) <= total, phase + ":count")
        if len(rows) == total:
            require(not page.get("has_more", False), phase + ":has-more")
            return rows, total
        require(items and page.get("next_offset") == len(rows), phase + ":cursor")
    raise ContractFailure(phase + ":page-bound")


def sort_value(row: dict, field: str):
    if field == "severity":
        value = str(row.get("severity") or "").casefold()
        return (SEVERITY.get(value, 5), value)
    if field == "resource_id":
        value = row.get("resource_name") or row.get("native_resource_id") or row.get("resource_id") or ""
    else:
        value = row.get(field) or ""
    return str(value).casefold()


def findings(client: httpx.Client, scan_id: str) -> tuple[dict, dict | None]:
    base = f"/api/scans/{quote(scan_id, safe='')}/findings"
    baseline, total = page_all(client, base + "?sort_by=severity&sort_order=asc", "findings:severity:asc")
    ids = [row.get("id") for row in baseline]
    require(len(set(ids)) == total and all(isinstance(item, str) for item in ids), "findings:ids")
    ordered = {}
    for field in SORTS:
        for direction in ("asc", "desc"):
            phase = f"findings:{field}:{direction}"
            rows, count = page_all(client, base + f"?sort_by={field}&sort_order={direction}", phase)
            require(count == total and {row.get("id") for row in rows} == set(ids), phase + ":conservation")
            previous = None
            previous_id = None
            for row in rows:
                key = sort_value(row, field)
                if previous is not None:
                    require((previous <= key if direction == "asc" else previous >= key), phase + ":order")
                    if previous == key:
                        require(previous_id <= row["id"], phase + ":tie")
                previous, previous_id = key, row["id"]
            ordered[f"{field}:{direction}"] = len(rows)
    detail = None
    if baseline:
        item_id = quote(baseline[0]["id"], safe="")
        detail = get_json(client, base + "/" + item_id, "finding-detail")
        if "download_url" in detail:
            artifact(client, detail, "finding-detail")
        else:
            require(detail.get("id") == baseline[0]["id"], "finding-detail:id")
    return {"total": total, "sorts": ordered}, detail


def run(args: argparse.Namespace, key: str) -> dict:
    require(bool(re.fullmatch(r"peaso_[a-f0-9]{32}_[A-Za-z0-9_-]{43}", key)), "key:format")
    receipt: dict = {"status": "passed", "source_version": args.source_version, "checks": {}}
    with httpx.Client(base_url=HOST, timeout=60, follow_redirects=False,
                      headers={"Authorization": "Bearer " + key}) as client:
        health = get_json(client, "/api/health", "health")
        require(health.get("source_version") == args.source_version, "health:source-version")
        if args.mode == "revoked":
            get_json(client, "/api/me", "revoked-key", status=401)
            receipt["checks"]["revoked_key_denied"] = True
            return receipt
        me = get_json(client, "/api/me", "identity")
        require(me.get("auth_kind") == "api_key" and me.get("tenant_id") == args.tenant_id, "identity:tenant")
        receipt["checks"]["identity"] = {"plan": me.get("plan"), "weekly_limit": me.get("weekly_limit"),
                                          "weekly_used": me.get("weekly_used")}
        scans = get_json(client, "/api/scans", "scans")
        require(any(row.get("id") == args.scan_id for row in scans.get("items", [])), "scans:owned")
        scan = get_json(client, "/api/scans/" + quote(args.scan_id, safe=""), "scan")
        require(scan.get("status") == "completed", "scan:completed")
        receipt["checks"]["findings"], _ = findings(client, args.scan_id)
        scan_path = "/api/scans/" + quote(args.scan_id, safe="")
        for fmt in ("json", "markdown"):
            response = client.get(scan_path + "/report", params={"format": fmt})
            require(response.status_code == 200, "report:" + fmt)
            if response.headers.get("content-type", "").startswith("application/json"):
                try:
                    value = response.json()
                except ValueError:
                    raise ContractFailure("report:" + fmt + ":json") from None
                if isinstance(value, dict) and "download_url" in value:
                    proof = artifact(client, value, "report:" + fmt)
                    require(proof["first"] == (b"{" if fmt == "json" else b"#"), "report:" + fmt + ":type")
                    proof.pop("first")
                    receipt["checks"]["report:" + fmt] = proof
                    continue
            body = response.content
            require(body.lstrip()[:1] == (b"{" if fmt == "json" else b"#"), "report:" + fmt + ":inline-type")
            receipt["checks"]["report:" + fmt] = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        for suffix in ("summary", "coverage", "resources"):
            path = scan_path + "/" + suffix
            if suffix == "summary":
                value = get_json(client, path, suffix)
                receipt["checks"][suffix] = {"finding_count": value.get("finding_count"), "coverage_count": value.get("coverage_count")}
            else:
                rows, total = page_all(client, path, suffix)
                receipt["checks"][suffix] = {"total": total, "pages_verified": (len(rows) + MAX_PAGE - 1) // MAX_PAGE}
        for kind in ("network", "iam", "privesc"):
            value = get_json(client, scan_path + "/graphs/" + kind, "graph:" + kind)
            if "download_url" in value:
                proof = artifact(client, value, "graph:" + kind)
                proof.pop("first")
                receipt["checks"]["graph:" + kind] = proof
            else:
                receipt["checks"]["graph:" + kind] = {"inline": True}
        connectors = get_json(client, "/api/connectors", "connectors")
        require(isinstance(connectors.get("items"), list), "connectors:items")
        for connector in connectors["items"]:
            auth = connector.get("auth", {})
            require(isinstance(auth, dict) and set(auth) <= {"configured", "fields"} and
                    "onboarding" not in connector, "connectors:sanitized")
        receipt["checks"]["connectors"] = len(connectors["items"])
        schedules = get_json(client, "/api/schedules", "schedules")
        require(isinstance(schedules.get("items"), list), "schedules:items")
        receipt["checks"]["schedules"] = len(schedules["items"])
        get_json(client, "/api/catalog/frameworks", "frameworks")
        get_json(client, "/api/catalog?view=summary", "catalog")
        receipt["checks"]["catalog"] = True
        get_json(client, "/api/api-keys", "key-manager-read", status=403)
        blocked = client.post(scan_path + "/cancel", json={})
        require(blocked.status_code == 403, "key-write-block")
        receipt["checks"]["read_only"] = True
        foreign = "/api/scans/" + quote(args.foreign_scan_id, safe="")
        get_json(client, foreign, "foreign-scan", status=404)
        get_json(client, foreign + "/report", "foreign-report", status=404)
        receipt["checks"]["foreign_tenant_denied"] = True
        after = get_json(client, "/api/me", "identity-after-reads")
        require(after.get("tenant_id") == me["tenant_id"] and
                after.get("plan") == me.get("plan") and
                after.get("weekly_limit") == me.get("weekly_limit") and
                after.get("weekly_used") == me.get("weekly_used"), "read-only-quota")
        receipt["checks"]["quota_unchanged"] = True
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("read", "revoked"), required=True)
    parser.add_argument("--source-version", required=True)
    parser.add_argument("--tenant-id")
    parser.add_argument("--scan-id")
    parser.add_argument("--foreign-scan-id")
    parser.add_argument("--key-fd", type=int, default=3)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "read" and not all((args.tenant_id, args.scan_id, args.foreign_scan_id)):
        parser.error("Read mode requires owned tenant/scan and a different tenant's scan ID")
    phase = "key-input"
    try:
        require(args.receipt.parent.is_dir() and not args.receipt.is_symlink(), "receipt:path")
        key_bytes = os.read(args.key_fd, 4096)
        require(b"\n" not in key_bytes.strip() and 20 <= len(key_bytes.strip()) <= 256, "key:input")
        key = key_bytes.decode("ascii").strip()
        phase = "external-read-contract"
        receipt = run(args, key)
        encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        fd = os.open(args.receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
        print(json.dumps({"status": "passed", "receipt": str(args.receipt), "checks": sorted(receipt["checks"])}))
        return 0
    except Exception as error:
        # No exception text, HTTP URL, request header or response body reaches logs.
        print(json.dumps({"status": "failed", "phase": phase, "error_type": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
