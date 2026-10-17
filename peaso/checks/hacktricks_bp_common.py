"""HackTricks Cloud Best Practices: per-check HackTricks page references.

Every native check carries the "HackTricks Cloud Best Practices" framework label
(see peaso.checks.catalog.mappings_for). Checks in the hacktricks_bp_* modules
are derived from a specific HackTricks Cloud attack-technique page; that page,
rather than the generic methodology page, becomes the framework reference.
Existing Prowler/Powerpipe-derived checks that already implement a HackTricks
technique are linked here (reference only) instead of being duplicated.
"""
from __future__ import annotations

import re

from .facts import Unavailable

HACKTRICKS_BASE = "https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/"
_PAGE = re.compile(r"^pentesting-cloud/[A-Za-z0-9_./-]+\.md$")

# check id -> tuple of HackTricks Cloud page paths (relative to the repository src/).
HACKTRICKS_PAGES: dict = {}
# check ids implemented by the hacktricks_bp_* modules (not merely linked).
HTBP_IDS: list = []


def link(check_id, *pages):
    """Associate a check id with the HackTricks Cloud page(s) it is derived from."""
    if not pages or any(not isinstance(p, str) or not _PAGE.fullmatch(p) or ".." in p for p in pages):
        raise ValueError("HackTricks pages must be src-relative pentesting-cloud/*.md paths")
    existing = HACKTRICKS_PAGES.get(check_id, ())
    HACKTRICKS_PAGES[check_id] = tuple(dict.fromkeys(existing + tuple(pages)))


def hacktricks_references(check_id):
    """HackTricks page URLs for a check (empty when only the generic methodology applies)."""
    return [HACKTRICKS_BASE + page for page in HACKTRICKS_PAGES.get(check_id, ())]


def native(item):
    """An object without any native field is not a collected resource: API-omission
    defaults must never turn it into PASS."""
    if isinstance(item, dict) and not any(not str(key).startswith("_") and key not in ("collection_status", "provenance") for key in item):
        raise Unavailable("native resource has no collected fields")
    return item


def ht_register(id, provider, category, kind, title, severity, control, remediation, *, pages, target="resource", dependencies=None):
    """peaso.checks.register plus the HackTricks page(s) the predicate is derived from."""
    from . import register
    registrar = register(id, provider, category, kind, title, severity, control, remediation, target=target,
                         dependencies=list(dependencies or [kind]))

    def apply(function):
        def evaluate(item, index):
            native(item)
            return function(item, index)
        evaluate.__name__ = function.__name__
        evaluate.__doc__ = function.__doc__
        registrar(evaluate)
        link(id, *pages)
        HTBP_IDS.append(id)
        return function
    return apply
