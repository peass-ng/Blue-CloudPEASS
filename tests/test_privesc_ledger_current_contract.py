"""Review ledger remains aligned with the active privilege technique contracts."""

import hashlib
import json
from pathlib import Path

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]


def test_every_active_technique_has_a_current_review_contract():
    entries = {entry["id"]: entry for entry in privesc.catalog()["entries"]}
    ledger = json.loads((ROOT / "docs/evidence-reviews/privesc.json").read_text())
    assert set(ledger["checks"]) == set(entries) | {"admin-equivalent"}
    assert ledger["catalog_techniques"] == len(entries)
    assert ledger["by_provider"] == {
        provider: sum(entry["provider"] == provider for entry in entries.values())
        for provider in ("aws", "gcp", "azure", "k8s")
    }
    for ident, entry in entries.items():
        row = ledger["checks"][ident]
        normalized = {key: value for key, value in entry.items() if not key.startswith("_")}
        digest = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
        assert row["reviewed_contract_sha256"] == digest, ident
        assert row["catalog_file"] == "peaso/privesc/catalog/" + entry["_file"], ident
        assert row["source"] == entry["source"], ident
        assert row["source_revision"] == entry.get("source_revision"), ident
        assert row["provider"] == entry["provider"], ident
        assert row["target_kind"] == entry["target"]["kind"], ident
        assert row["requirement_contract"] == entry["requires"], ident
        assert row["conditions_retained"] == [condition["id"] for condition in entry.get("conditions", [])], ident
        assert row["blockers_retained"] == entry.get("blockers", []), ident
        assert row["review_status"] == "source_reviewed", ident
        assert row["purpose"], ident
