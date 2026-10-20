"""HackTricks Cloud Best Practices framework: per-check page references and module contract."""
import os
from pathlib import Path

import pytest

from peaso.checks import CHECKS, HACKTRICKS, HACKTRICKS_URL
from peaso.checks.fixtures import CASES
from peaso.checks.hacktricks_bp_common import HACKTRICKS_BASE, HACKTRICKS_PAGES, HTBP_IDS, link
from peaso.checks.hacktricks_bp_links import LINKS
from peaso.checks.hacktricks_scope import includes

REGISTRY = {c.id: c for c in CHECKS}


def test_htbp_ids_are_registered_unique_and_prefixed():
    assert HTBP_IDS and len(HTBP_IDS) == len(set(HTBP_IDS))
    for cid in HTBP_IDS:
        check = REGISTRY[cid]
        assert cid.startswith(check.provider + ".htbp."), cid
        assert (HACKTRICKS in check.frameworks) == includes(cid)
        assert {"pass", "fail", "missing", "malformed"} <= set(CASES[cid]), cid


def test_linked_checks_exist_and_are_not_reimplemented():
    for cid in LINKS:
        assert cid in REGISTRY, cid
        assert cid not in HTBP_IDS


@pytest.mark.parametrize("cid", sorted(set(HTBP_IDS) | set(LINKS)))
def test_mapping_reference_is_the_hacktricks_page(cid):
    check = REGISTRY[cid]
    if not includes(cid):
        assert HACKTRICKS not in check.mapping
        return
    mapping = check.mappings[HACKTRICKS] if hasattr(check, "mappings") else None
    from peaso.checks.catalog import mappings_for
    mapping = mapping or mappings_for(cid, check.category, check.control)[HACKTRICKS]
    pages = [HACKTRICKS_BASE + p for p in HACKTRICKS_PAGES[cid]]
    assert mapping["reference"] == pages[0] and mapping["references"] == pages


def test_unlinked_checks_keep_generic_methodology_reference():
    from peaso.checks.catalog import mappings_for
    check = next(c for c in CHECKS if c.id not in HACKTRICKS_PAGES and includes(c.id))
    assert mappings_for(check.id, check.category, check.control)[HACKTRICKS]["reference"] == HACKTRICKS_URL


@pytest.mark.parametrize("page", ["../etc/passwd.md", "https://x/y.md", "pentesting-cloud/a b.md", "pentesting-cloud/x.txt"])
def test_link_rejects_non_page_paths(page):
    with pytest.raises(ValueError):
        link("x.y", page)


def test_referenced_pages_exist_in_hacktricks_checkout():
    root = os.environ.get("PEASO_HACKTRICKS_ROOT")
    if not root:
        pytest.skip("set PEASO_HACKTRICKS_ROOT to a hacktricks-cloud checkout to verify page paths")
    missing = sorted({p for pages in HACKTRICKS_PAGES.values() for p in pages if not (Path(root) / "src" / p).is_file()})
    assert not missing
