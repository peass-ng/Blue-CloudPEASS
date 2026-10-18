"""Audit rule links against one pinned HackTricks Cloud source tree.

A page reference is provenance, not proof that every technique on that page is
detected or that a matched event is malicious. This ledger deliberately keeps
those claims separate.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from scripts.attack_detection_technique_inventory import build_inventory


_SOURCE_PATH = re.compile(
    r"/HackTricks-wiki/hacktricks-cloud/blob/(?P<revision>[0-9a-f]{40})/"
    r"src/pentesting-cloud/(?P<page>[^?#]+)\Z"
)


def source_page(reference: str, revision: str) -> str | None:
    """Return a page only for a link to the exact reviewed source revision."""
    if not isinstance(reference, str):
        return None
    parsed = urlsplit(reference)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query:
        return None
    match = _SOURCE_PATH.fullmatch(parsed.path)
    if match is None or match.group("revision") != revision:
        return None
    page = match.group("page")
    if not page.endswith(".md") or any(part in {"", ".", ".."} for part in page.split("/")):
        return None
    return page


def build_ledger(corpus_root: Path, rules_dir: Path, revision: str) -> dict:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("source_revision_must_be_full_git_sha")
    source = corpus_root / "src" / "pentesting-cloud"
    if not source.is_dir():
        source = corpus_root / "pentesting-cloud"
    if not source.is_dir():
        raise ValueError("corpus_root_missing")
    inventory = build_inventory(corpus_root, source_revision=revision)
    candidate_pages = {row["path"] for row in inventory["sections"]}
    rows = []
    referenced_pages = set()
    for path in sorted(rules_dir.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(rule, dict):
            raise ValueError(f"invalid_rule:{path.name}")
        refs = rule.get("references", [])
        if not isinstance(refs, list):
            raise ValueError(f"invalid_references:{path.name}")
        pages = sorted({page for ref in refs if (page := source_page(ref, revision))})
        missing = [page for page in pages if not (source / page).is_file()]
        referenced_pages.update(page for page in pages if page not in missing)
        rows.append({
            "rule_file": path.name,
            "technique_id": rule.get("x_hacktricks_technique_id"),
            "provider": (rule.get("logsource") or {}).get("product"),
            "source_pages": pages,
            "missing_source_pages": missing,
        })
    if not rows:
        raise ValueError("no_rules")
    return {
        "source_revision": revision,
        "meaning": "Source page references only; page counts are not technique or detection coverage",
        "rule_count": len(rows),
        "rules_without_exact_source_page": [r["rule_file"] for r in rows if not r["source_pages"]],
        "rules_with_missing_source_page": [r["rule_file"] for r in rows if r["missing_source_pages"]],
        "candidate_page_count": len(candidate_pages),
        "rule_referenced_candidate_page_count": len(candidate_pages & referenced_pages),
        "rule_referenced_pages": sorted(referenced_pages),
        "rules": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--rules-dir", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = build_ledger(args.corpus_root, args.rules_dir, args.source_revision)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "rules"}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
