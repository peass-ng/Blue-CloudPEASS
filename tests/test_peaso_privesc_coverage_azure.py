"""Azure / Entra ID privesc coverage against the synced HackTricks Cloud catalog.

The ledger (docs/privesc-ledgers/privesc-azure.md, or PEASO_PRIVESC_LEDGER_AZURE) maps
HackTricks headings to catalog ids. When a hacktricks-cloud checkout at the synced revision is available,
every heading of az-privilege-escalation/** must have a ledger row.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path

import pytest

from peaso.privesc.schema import checkout_revision, load_catalog, revision_matches
from peaso.privesc.versioned_catalog import LEGACY_REVISION
import yaml

PREFIX = "src/pentesting-cloud/azure-security/"
ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "risk_rules" / "hacktricks-privesc-source.json").read_text(encoding="utf-8"))
REVISION = MANIFEST["revision"]
CATALOG = ROOT / "peaso" / "privesc" / "catalog" / "azure"
LEDGER = Path(os.environ.get("PEASO_PRIVESC_LEDGER_AZURE", str(ROOT / "docs" / "privesc-ledgers" / "privesc-azure.md")))
CHECKOUTS = [p for p in os.environ.get("HACKTRICKS_CLOUD_ROOT", "").split(os.pathsep) if p] + [
    str(ROOT.parent / "htc"), str(ROOT.parent / "hacktricks-cloud"), str(Path.home() / "git" / "hacktricks-cloud")]
CURRENT = re.compile(r"^\| `(azure-[a-z0-9-]+)` \| `([^`]+)` \| (ACTIVE|RETIRED) \| (.*) \|$")


def _current_rows():
    text = LEDGER.read_text(encoding="utf-8")
    assert f"## Current CSPM catalog reconciliation (HackTricks Cloud `{REVISION}`)" in text
    section = text.split("## Current CSPM catalog reconciliation", 1)[1]
    return {m.group(1): (m.group(2), m.group(3), m.group(4))
            for line in section.splitlines() if (m := CURRENT.match(line))}

def _azure_entries():
    result = load_catalog()
    assert not [e for e in result["errors"] if e.startswith("azure/")], [e for e in result["errors"] if e.startswith("azure/")]
    return {e["id"]: e for e in result["entries"] if e["provider"] == "azure"}

def test_ledger_mapped_ids_exist_in_catalog():
    entries = _azure_entries()
    mapped = _mapped_ledger()
    current = _current_rows()
    retired = {ident for ident, (_, status, _) in current.items() if status == "RETIRED"}
    excluded = {item.get("id"): item for path in CATALOG.glob("_excluded*.yaml")
                for item in (yaml.safe_load(path.read_text()) or []) if item.get("id")}
    assert mapped, "Azure ledger has no mapped rows"
    missing = sorted({(key, i) for key, ids in mapped.items() for i in ids if i not in entries and i not in retired})
    assert not missing, missing
    assert retired <= excluded.keys()
    assert all(mapped.values()), "Azure ledger has a MAPPED row without catalog ids"
    unmapped = sorted(set(entries) - {i for ids in mapped.values() for i in ids})
    assert not unmapped, unmapped
    source_mismatches = sorted(
        i for i, entry in entries.items()
        if not any(i in mapped.get(source.removeprefix(PREFIX), [])
                   for source in (entry["source"] if isinstance(entry["source"], list) else [entry["source"]])))
    assert not source_mismatches, source_mismatches
    assert {i for i, (_, status, _) in current.items() if status == "ACTIVE"} == set(entries)

def test_azure_entries_cite_refreshed_revision_and_azure_pages():
    entries = _azure_entries()
    assert re.fullmatch(r"[0-9a-f]{40}", REVISION)
    assert LEDGER.is_file(), f"azure privesc ledger missing: {LEDGER}"
    header = LEDGER.read_text(encoding="utf-8").splitlines()[0]
    ledger_revision = re.search(r"HackTricks Cloud ([0-9a-f]{7,40})\b", header)
    assert ledger_revision and revision_matches(ledger_revision.group(1), LEGACY_REVISION), header
    # The v4 section and manifest hashes describe earlier source and catalog
    # bytes. This reviewed overlay records current active and retired deltas.
    current = _current_rows()
    assert current
    assert all(source.startswith(PREFIX) and reason.strip() for source, _, reason in current.values())
    assert all(e["source"].startswith(PREFIX) for e in entries.values())

def _parse_ledger():
    rows = {}
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]
        if len(cells) == 5:
            rows[cells[0].strip("`")] = (cells[3], cells[4])
    return rows

def _legacy_mapped_ledger():
    return {key: re.findall(r"`((?:azure|entra)-[a-z0-9-]+)`", detail)
            for key, (status, detail) in _parse_ledger().items() if status == "MAPPED"}


def _mapped_ledger():
    mapped = _legacy_mapped_ledger()
    for ident, (source, status, _) in _current_rows().items():
        if status == "ACTIVE":
            mapped.setdefault(source.removeprefix(PREFIX), []).append(ident)
    return mapped

def test_ledger_has_mappings_and_known_statuses():
    assert LEDGER.is_file(), f"azure privesc ledger missing: {LEDGER}"
    rows = _parse_ledger()
    assert _mapped_ledger(), "Azure ledger has no mapped rows"
    assert {s for s, _ in rows.values()} <= {"MAPPED", "EXCLUDED", "NEEDS SCHEMA", "STRUCTURAL", "SUBSECTION"}

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")

def _slug(text):
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    return "".join(ch if (ch.isalnum() or ch in "_-") else "-" if ch.isspace() else "" for ch in text)

def _headings(page):
    seen, in_code = Counter(), False
    for line in page.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        match = None if in_code else _HEADING.match(line)
        if match:
            slug = _slug(match.group(2))
            yield slug if seen[slug] == 0 else f"{slug}-{seen[slug]}"
            seen[slug] += 1

def test_every_privesc_heading_has_a_ledger_row():
    assert LEDGER.is_file(), f"azure privesc ledger missing: {LEDGER}"
    roots = [Path(p) for p in CHECKOUTS if (Path(p) / PREFIX).is_dir() and revision_matches(checkout_revision(Path(p)), REVISION)]
    if not roots:
        pytest.skip(f"no hacktricks-cloud checkout at {REVISION}")
    base = roots[0] / PREFIX
    rows = _parse_ledger()
    missing = [f"{p.relative_to(base)}#{a}" for p in sorted((base / "az-privilege-escalation").rglob("*.md"))
               for a in _headings(p) if f"{p.relative_to(base)}#{a}" not in rows]
    assert not missing, missing
