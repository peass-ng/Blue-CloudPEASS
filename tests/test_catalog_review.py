"""The review must cover the whole pinned catalog, not only populated labs."""

import collections
import csv
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re

from bluepeass.finding_filters import blacklist_rules


def test_every_pinned_suite_has_full_review_evidence():
    rows = list(csv.DictReader(Path("docs/hardening-catalog-review.csv").open()))
    expected = {"aws-compliance": 679, "aws-perimeter": 62,
                "azure-compliance": 476, "azure-perimeter": 14,
                "gcp-compliance": 202, "gcp-perimeter": 33,
                "kubernetes-compliance": 781}
    assert collections.Counter(row["suite"] for row in rows) == expected
    assert len({row["control_id"] for row in rows}) == 2247
    catalog = json.loads(Path("bluepeass/hardening_catalog.json").read_text())
    versions = {entry["mod"]: entry["version"] for entries in catalog.values() for entry in entries}
    for row in rows:
        assert row["version"] == versions[row["suite"]]
        assert re.fullmatch("[0-9a-f]{64}", row["sql_sha256"])
        assert re.fullmatch("[0-9a-f]{64}", row["query_parameters_sha256"])
        assert row["source_url"].startswith("https://github.com/turbot/")
        assert row["disposition"] and row["rationale"]
    assert any(row["context_queries"] for row in rows if row["provider"] == "aws")
    assert any(row["context_queries"] for row in rows if row["provider"] == "azure")
    assert any(row["context_queries"] for row in rows if row["provider"] == "gcp")
    assert any(row["context_queries"] for row in rows if row["provider"] == "kubernetes")


def test_hardening_rules_and_duplicate_sources_exist_in_the_reviewed_catalog():
    rows = list(csv.DictReader(Path("docs/hardening-catalog-review.csv").open()))
    indexed = {row["control_id"]: row for row in rows}
    for rule in blacklist_rules():
        if "hardening" not in rule["sections"]:
            continue
        matches = [row for row in rows if row["provider"] == rule["provider"] and any(fnmatchcase(row["control_id"], pattern) for pattern in rule.get("control_patterns", []))]
        assert matches, rule["id"]
        if rule.get("duplicate_of"):
            source = indexed[rule["duplicate_of"]]
            assert all(row["sql_normalized_sha256"] == source["sql_normalized_sha256"] for row in matches), rule["id"]
