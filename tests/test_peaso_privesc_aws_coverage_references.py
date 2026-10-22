"""Excluded AWS routes must not claim coverage by retired techniques."""

from pathlib import Path
import re

import yaml

from peaso.privesc import versioned_catalog as catalog
from peaso.privesc.schema import CATALOG_DIR

_CLAIM = re.compile(
    r"covered by|modelled by|modeled by|modelled as|modeled as|"
    r"folded into|merged into|represented by|implemented by|current .* technique is",
    re.IGNORECASE,
)
_IDS = re.compile(r"aws-[a-z0-9]+(?:-[a-z0-9]+)+")


def test_aws_exclusions_do_not_claim_retired_routes_cover_them():
    root = Path(CATALOG_DIR) / "aws"
    active = {
        item["id"]
        for path in root.glob("*.yaml")
        if not path.name.startswith("_excluded")
        for item in (yaml.safe_load(path.read_text()) or [])
    }
    stale = []
    for path in root.glob("_excluded*.yaml"):
        for item in (yaml.safe_load(path.read_text()) or []):
            reason = item.get("reason", "")
            if _CLAIM.search(reason):
                stale.extend((path.name, item["technique"], ident)
                             for ident in _IDS.findall(reason) if ident not in active)
    assert not stale


def test_coverage_text_revision_preserves_exact_previous_catalog():
    old = {
        "schema": catalog.BINDING_SCHEMA,
        "manifest_sha256": catalog.STALE_COVERAGE_689_PREVIOUS_MANIFEST,
        "effective_tree_sha256": catalog.STALE_COVERAGE_689_PREVIOUS_TREE,
        "source_revision": catalog.V4_REVISION,
    }
    ident = "aws-sts-assumerole-trusted"
    previous, status = catalog.lookup_entries([ident], old)
    assert status == "exact_previous_current"
    assert set(previous) == {ident}
    assert len(catalog._verified_stale_coverage_689_previous()) == 689
