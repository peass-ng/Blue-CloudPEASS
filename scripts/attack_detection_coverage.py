"""Audit rule links against a pinned HackTricks Cloud page inventory.

This is a page-reference ledger, not a claim that every technique on a linked
page is detected. It deliberately leaves pages without exact references open.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml


GITHUB_SOURCE = re.compile(
    r"/HackTricks-wiki/hacktricks-cloud/blob/([0-9a-f]{40})/(src/pentesting-cloud/.+\.md)\Z",
    re.IGNORECASE,
)


def _reference_page(reference: object, source_revision: str) -> str | None:
    if not isinstance(reference, str):
        return None
    url = urlsplit(reference)
    if url.scheme != "https" or url.netloc.lower() != "github.com":
        return None
    match = GITHUB_SOURCE.fullmatch(unquote(url.path))
    return match.group(2) if match and match.group(1).lower() == source_revision.lower() else None


def build_ledger(inventory: dict, catalog: dict, rule_dir: Path, rules_ref: str) -> dict:
    pages = inventory["pages"]
    paths = {page["path"] for page in pages}
    if len(paths) != len(pages):
        raise ValueError("duplicate corpus page path")
    catalog_pages: dict[str, set[str]] = defaultdict(set)
    for entry in catalog["catalog"]:
        path = entry.get("source", "").split("#", 1)[0]
        if path in paths:
            catalog_pages[entry["id"]].add(path)

    page_rules: dict[str, set[str]] = defaultdict(set)
    unresolved: list[dict[str, str]] = []
    rule_files = sorted(rule_dir.glob("*.yml"))
    if not rule_files:
        raise ValueError("empty rule directory")
    for file in rule_files:
        rule = yaml.safe_load(file.read_text(encoding="utf-8"))
        rule_id = str(rule["id"])
        technique_id = str(rule["x_hacktricks_technique_id"])
        linked = {_reference_page(ref, inventory["source_revision"]) for ref in rule.get("references", [])}
        linked.discard(None)
        linked.update(catalog_pages.get(technique_id, set()))
        linked &= paths
        if not linked:
            unresolved.append({"rule_id": rule_id, "rule_file": file.name,
                               "technique_id": technique_id})
        for path in linked:
            page_rules[path].add(rule_id)

    rows = [{"provider": page["provider"], "path": page["path"],
             "headings": len(page["headings"]),
             "linked_rule_ids": sorted(page_rules[page["path"]])}
            for page in pages]
    provider_counts = {provider: {
        "pages": sum(row["provider"] == provider for row in rows),
        "pages_with_linked_rules": sum(row["provider"] == provider and bool(row["linked_rule_ids"]) for row in rows),
    } for provider in ("aws", "gcp", "azure", "k8s")}
    return {
        "meaning": "Page references only; no technique recall or false-positive guarantee",
        "corpus_revision": inventory["source_revision"],
        "catalog_revision": catalog["source_catalog_revision"],
        "rules_ref": rules_ref,
        "rule_count": len(rule_files),
        "page_count": len(rows),
        "provider_counts": provider_counts,
        "rules_without_page_link": unresolved,
        "pages": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--rules-ref", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    result = build_ledger(inventory, catalog, args.rules, args.rules_ref)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("rule_count", "page_count", "provider_counts")}, sort_keys=True))


if __name__ == "__main__":
    main()
