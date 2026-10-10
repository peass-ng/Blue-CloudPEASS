#!/usr/bin/env python3
"""Validate the privilege-escalation catalog (peaso/privesc/catalog/**.yaml).

Checks every entry with peaso.privesc.schema.validate_entry (unique ids, known
target kinds / selector keys / placeholders / requirement fields, hacktricks
source file exists) and summarises every key the evaluator does not know yet
(selector keys, placeholders, target kinds, blockers), so catalog authors and
the evaluator owner can see what still needs a schema extension.

Optionally (--permissions) warns about AWS/GCP/Azure actions that are not in
the repository's <provider>_permissions_cat.yaml lists (typos, invented
permissions). Exit status is 1 when any entry is invalid.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from peaso.privesc.schema import CATALOG_DIR, HACKTRICKS_CLOUD, load_catalog  # noqa: E402

UNKNOWN_PATTERNS = {
    "selector_key": re.compile(r"unknown (?:source_)?selector key '([^']+)'"),
    "placeholder": re.compile(r"unknown placeholders \[([^\]]+)\]"),
    "target_kind": re.compile(r"unknown target kind '([^']+)'"),
    "blocker": re.compile(r"unknown blocker '([^']+)'"),
    "field": re.compile(r"unknown (?:target )?fields \[([^\]]+)\]"),
    "requirement_field": re.compile(r"unknown requirement fields? \[([^\]]+)\]"),
}


def unknown_keys(messages):
    found = defaultdict(Counter)
    for message in messages:
        for kind, pattern in UNKNOWN_PATTERNS.items():
            for match in pattern.finditer(message):
                for value in match.group(1).split(","):
                    found[kind][value.strip().strip("'\"")] += 1
    return {kind: dict(sorted(counter.items())) for kind, counter in sorted(found.items())}


# gcp_permissions_cat.yaml stores service-prefixed IAM permissions with the slash mangled to a dash
# (iam.googleapis.com-workloadIdentityPools.create); the catalog uses the real IAM names
# (iam.googleapis.com/workloadIdentityPools.create). Both forms compare equal.
def normalize_permission(provider, value):
    value = str(value).lower()
    if provider == "gcp":
        value = re.sub(r"^([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:googleapis|netapp)\.com)[-/]", r"\1/", value)
    return value

# Known permissions missing from the generated *_permissions_cat.yaml (synced from hacktricks; do not edit it):
# evaluator pseudo-permissions and real IAM permissions newer than the synced list.
PSEUDO_PERMISSIONS = {
    "gcp": {
        # Cloud Identity group membership: derived from group OWNER/MANAGER roles or Workspace admin roles.
        "cloudidentity.groups.memberships.create",
        # Cloud Run SSH into running instances (IAM reference: roles/run.sshUser / run.sshRoot).
        *(f"run.{kind}.{verb}" for kind in ("jobs", "services", "workerpools") for verb in ("sshread", "sshroot")),
    },
}

def permission_lists():
    perms = {}
    for provider in ("aws", "gcp", "azure"):
        path = ROOT / f"{provider}_permissions_cat.yaml"
        if not path.is_file():
            continue
        data = yaml.safe_load(path.read_text()) or {}
        values = set()
        for bucket in data.values() if isinstance(data, dict) else []:
            values.update(normalize_permission(provider, v) for v in bucket or [])
        perms[provider] = values | PSEUDO_PERMISSIONS.get(provider, set())
    return perms


def unknown_permissions(entries, perms):
    out = defaultdict(set)
    for entry in entries:
        provider = entry["provider"]
        known = perms.get(provider)
        if not known:
            continue
        requires = entry.get("requires") or {}
        reqs = list(requires.get("all_of") or []) + [r for g in requires.get("any_of") or [] for r in g]
        for req in reqs:
            action = req.get("action") or req.get("permission") if isinstance(req, dict) else None
            if not isinstance(action, str) or "*" in action:
                continue
            if normalize_permission(provider, action) not in known:
                out[action].add(entry["id"])
    return {k: sorted(v) for k, v in sorted(out.items())}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--catalog-dir", default=str(CATALOG_DIR))
    parser.add_argument("--hacktricks-root", default=str(HACKTRICKS_CLOUD),
                        help="hacktricks-cloud checkout used to verify source paths (skipped when absent)")
    parser.add_argument("--permissions", action="store_true", help="warn on actions missing from *_permissions_cat.yaml")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--quiet", action="store_true", help="do not list warnings")
    args = parser.parse_args(argv)

    loaded = load_catalog(args.catalog_dir, hacktricks_root=args.hacktricks_root)
    entries, errors, warnings = loaded["entries"], loaded["errors"], loaded["warnings"]
    per_provider = Counter(e["provider"] for e in entries)
    report = {
        "catalog_dir": args.catalog_dir,
        "hacktricks_root": args.hacktricks_root if Path(args.hacktricks_root).is_dir() else None,
        "valid_entries": len(entries),
        "valid_by_provider": dict(sorted(per_provider.items())),
        "excluded_entries": loaded["excluded"],
        "files": len(loaded["files"]),
        "errors": errors,
        "warnings": warnings,
        "unknown_keys": unknown_keys(errors + warnings),
    }
    if args.permissions:
        report["unknown_permissions"] = unknown_permissions(entries, permission_lists())
    if args.json:
        print(json.dumps(report, indent=2))
        return 1 if errors else 0

    print(f"catalog: {args.catalog_dir}")
    if report["hacktricks_root"] is None:
        print(f"note: hacktricks-cloud not found at {args.hacktricks_root}; source paths not verified")
    print(f"valid entries: {len(entries)} {report['valid_by_provider']}  excluded: {loaded['excluded']}  files: {report['files']}")
    print(f"errors: {len(errors)}  warnings: {len(warnings)}")
    for error in errors:
        print(f"  ERROR {error}")
    if not args.quiet:
        for warning in warnings:
            print(f"  WARN  {warning}")
    if report["unknown_keys"]:
        print("keys unknown to the evaluator:")
        for kind, values in report["unknown_keys"].items():
            print(f"  {kind}: " + ", ".join(f"{k} (x{n})" for k, n in values.items()))
    else:
        print("keys unknown to the evaluator: none")
    if args.permissions:
        missing = report["unknown_permissions"]
        print(f"actions not in *_permissions_cat.yaml: {len(missing)}")
        for action, ids in missing.items():
            print(f"  {action}: {', '.join(ids[:5])}{' ...' if len(ids) > 5 else ''}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
