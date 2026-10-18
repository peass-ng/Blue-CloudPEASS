"""Small native catalog view for ordinary console navigation."""
from functools import lru_cache


@lru_cache(maxsize=1)
def summary():
    from peaso.analysis import ANALYSIS_CHECKS
    from peaso.checks import CHECKS as REGISTERED_CHECKS
    from peaso.checks.native_only import automated_checks, scope as automation_scope, automated_coverage, automated_inventory_types
    CHECKS = automated_checks(REGISTERED_CHECKS)
    from peaso.checks.catalog import coverage, framework_catalog
    from peaso.collectors import supported_types
    from peaso.engine import CATEGORIES, FRAMEWORK_ALIASES, PROVIDERS, SCHEMA_VERSION

    checks = [{"id": c.id, "provider": c.provider, "category": c.category, "type": c.kind,
               "title": c.title, "severity": c.severity} for c in CHECKS]
    checks.extend({key: c[key] for key in ("id", "provider", "category", "type", "title", "severity")} for c in ANALYSIS_CHECKS)
    names = sorted({name for c in CHECKS for name in c.frameworks})
    return {"schema_version": SCHEMA_VERSION, "view": "summary", "details_url": "/api/catalog",
            "providers": list(PROVIDERS), "categories": list(CATEGORIES),
            "inventories": {provider: automated_inventory_types(provider, supported_types(provider)) for provider in PROVIDERS},
            "checks": checks, "framework_versions": framework_catalog(), "upstream_coverage": automated_coverage(coverage()), "automation_scope": automation_scope(),
            "frameworks": [{"id": next((key for key, value in FRAMEWORK_ALIASES.items() if value == name), name),
                            "name": name} for name in names],
            "limitations": ["Compact selector metadata; complete rule evidence and review mappings are available from /api/catalog.",
                            "Framework mappings are review guidance, not certification. Pending references remain unsupported."]}


@lru_cache(maxsize=1)
def frameworks_view():
    """Framework/version selector list with counts only (no checks, no per-version check id lists)."""
    from peaso.checks import CHECKS as REGISTERED_CHECKS
    from peaso.checks.native_only import automated_checks, scope as automation_scope, automated_coverage, automated_inventory_types
    CHECKS = automated_checks(REGISTERED_CHECKS)
    from peaso.checks.catalog import coverage, framework_catalog
    from peaso.engine import PROVIDERS, SCHEMA_VERSION, framework_labels

    versions = [{key: value for key, value in row.items() if key != "native_check_ids"} for row in framework_catalog()]
    return {"schema_version": SCHEMA_VERSION, "view": "frameworks", "details_url": "/api/catalog",
            "providers": list(PROVIDERS), "frameworks": framework_labels([{"frameworks": c.frameworks} for c in CHECKS]),
            "framework_versions": versions, "upstream_coverage": automated_coverage(coverage()), "automation_scope": automation_scope(),
            "limitations": ["Framework and checklist-version selectors only; per-version native check ids are in /api/catalog?view=summary.",
                            "Framework mappings are review guidance, not certification. Pending references remain unsupported."]}
