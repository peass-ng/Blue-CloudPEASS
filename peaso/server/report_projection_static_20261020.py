"""API report projections copied exactly from the reviewed engine source.

These functions use archived report fields and tenant-bound public catalog
lookups. They never import the engine, checks registry, or analysis package.
SOURCE_SHA256 records the source generation; focused tests bind both that
identity and the function ASTs to the real engine in a separate process.
"""
import copy

SOURCE_SHA256 = {'peaso/engine.py': '8e00227aa81c91869e025f7f4c18426e6a2383c3eff05ae7d904fd63c34bfe5b',
 'peaso/privesc/schema.py': '6de9324c85af2bd58d1e2feab6cf255b4b2c2f17704668371c8cc4fcad2de674',
 'peaso/privesc/versioned_catalog.py': 'b14f581917d7c626600cf9ebb0eecfec69f2055787efaa143bda0faff7683b36',
 'peaso/privesc/effective_permissions/principal_evidence.py': '2c4bd5e2e2fa33db271b963387787003a42e1c741dad27b22e7b37f23fc2f7e3',
 'peaso/privesc/bulk_principal_tranche.json': '6cb1c21ba90b1ae08d0e5671efa373c8711d42cdb97d3f9055f84d3a239428a8',
 'peaso/remediation.py': '32cec77aafda1498ff57831c11756c195985d8a26a02fc30879e232cf446081b'}


ADMIN_EQUIVALENT_TECHNIQUE = {
    "id": "admin-equivalent", "title": "Principal already administers the target scope", "provider": None, "service": "iam",
    "summary": "The principal's collected grants are equivalent to administrator of the scope; no escalation step is needed.",
    "required_permissions": {"all_of": ["administrator-equivalent grant on the scope"], "any_of": [],
                             "leaves": ["administrator-equivalent grant on the scope"],
                             "alternatives": [["administrator-equivalent grant on the scope"]]}, "requires": {},
    "source": None, "source_revision": None, "conditions": [], "blockers": [], "severity": "critical", "catalog_confidence": "derived",
    "mitigation": "Review why this principal needs full administrative control; prefer scoped, time-bound access.", "references": []}


def _permission_text(requirement):
    if not isinstance(requirement, dict):
        return str(requirement)
    for key in ("action", "data_action", "entra_permission", "graph_app_permission", "entra_role", "entra_pim_eligible_role", "entra_tenant_setting"):
        if requirement.get(key):
            text = str(requirement[key])
            break
    else:
        if requirement.get("verb"):
            resource = "/".join(str(requirement[k]) for k in ("resource", "subresource") if requirement.get(k))
            group = requirement.get("api_group")
            text = f"{requirement['verb']} {group + '/' if group else ''}{resource}"
        elif requirement.get("entra_owner_of"):
            text = f"owner of {requirement['entra_owner_of']}"
        else:
            text = ", ".join(f"{k}={v}" for k, v in sorted(requirement.items()))
    where = requirement.get("resource") if "action" in requirement or "data_action" in requirement else None
    where = where or requirement.get("scope") or requirement.get("namespace") or requirement.get("resource_name")
    return f"{text} on {where}" if where and where != "*" else text


def _requirement_text(item):
    """Text of one requires item: a leaf requirement, or a nested {all_of}/{any_of} group rendered recursively
    ("(a AND b)", "(a OR (b AND c))"); a list inside any_of is one conjunction."""
    from peaso.privesc.schema import is_group
    if not is_group(item):
        return _permission_text(item)
    key = "all_of" if "all_of" in item else "any_of"
    parts = ["(" + " AND ".join(_requirement_text(c) for c in child) + ")" if isinstance(child, list) and len(child) != 1
             else _requirement_text(child[0] if isinstance(child, list) else child) for child in item.get(key) or []]
    if len(parts) == 1:
        return parts[0]
    return "(" + (" AND " if key == "all_of" else " OR ").join(parts) + ")"


def _required_permissions(requires):
    """Readable required permissions. all_of / any_of keep the catalog's top-level structure (nested groups are
    rendered by _requirement_text); leaves lists every leaf permission (flatten_requirements) and alternatives the
    disjunctive normal form (expand_requires: each alternative is a set of permissions that together suffice)."""
    from peaso.privesc.schema import CatalogError, expand_requires, flatten_requirements
    out = {"all_of": [_requirement_text(r) for r in requires.get("all_of") or []],
           "any_of": [[_requirement_text(r) for r in (group if isinstance(group, list) else [group])] for group in requires.get("any_of") or []],
           "leaves": list(dict.fromkeys(_permission_text(r) for r in flatten_requirements(requires)))}
    try:
        out["alternatives"] = [[_permission_text(r) for r in alternative] for alternative in expand_requires(requires)]
    except CatalogError:
        out["alternatives"] = None  # beyond the evaluator's expansion cap; the structured all_of/any_of still apply
    return out


def privesc_technique_details(technique_ids, *, catalog_binding=None, tenant_id=None):
    """Catalog details (summary, required permissions, HackTricks source, conditions, mitigation) per technique id."""
    try:
        from peaso.privesc.versioned_catalog import lookup_entries
        entries, lookup_status = lookup_entries(technique_ids, catalog_binding, tenant_id=tenant_id)
    except ImportError:
        entries, lookup_status = {}, "catalog_unavailable"
    details = {}
    for technique in technique_ids:
        if technique == "admin-equivalent" and lookup_status in ("exact_bounded_v5", "exact_additive_v4", "exact_legacy", "legacy_unversioned_fallback"):
            details[technique] = dict(copy.deepcopy(ADMIN_EQUIVALENT_TECHNIQUE), catalog_lookup_status="synthetic")
            continue
        entry = entries.get(technique)
        if entry is None:
            details[technique] = {"id": technique, "unknown": True, "catalog_lookup_status": lookup_status}
            continue
        requires = entry.get("requires") or {}
        from peaso.privesc.effective_permissions.principal_evidence import BULK_CONTRACT
        if technique in BULK_CONTRACT:
            requires = BULK_CONTRACT[technique]["requires"]
        details[technique] = {
            "id": technique, "title": entry.get("title"), "provider": entry.get("provider"), "service": entry.get("service"),
            "summary": entry.get("summary"), "requires": copy.deepcopy(requires),
            "required_permissions": _required_permissions(requires),
            "source": entry.get("source"), "source_revision": entry.get("source_revision"),
            "conditions": copy.deepcopy(entry.get("conditions") or []), "blockers": list(entry.get("blockers") or []),
            "severity": entry.get("severity"), "catalog_confidence": entry.get("confidence"),
            "mitigation": entry.get("mitigation"), "references": list(entry.get("references") or []),
            "catalog_lookup_status": lookup_status}
    return details


def finding_frameworks(finding, check_frameworks):
    """The labels of one finding: its explicit list, else its check's default list."""
    if "frameworks" in finding:
        return list(finding["frameworks"])
    return list((check_frameworks or {}).get(finding.get("check_id"), []))


CHECK_META_ENCODING = {"version": 1, "per_check_marker": "_derived",
                       "r": "description", "m": "remediation_templates.summary"}


def hydrate_finding(finding, check_frameworks=None, check_meta=None, check_meta_encoding=None,
                    remediation_templates=None):
    """One finding with its per-check defaults (frameworks and CHECK_META_FIELDS) restored; not modified in place."""
    defaults = (check_meta or {}).get(finding.get("check_id")) or {}
    encoded = check_meta_encoding == CHECK_META_ENCODING
    flags = defaults.get("_derived", "") if encoded else ""
    if not isinstance(flags, str) or flags not in {"r", "m", "rm"}:
        flags = ""
    missing = {field: value for field, value in defaults.items()
               if field not in finding and (field != "_derived" or not encoded)}
    if "r" in flags and "rationale" not in finding and "rationale" not in defaults:
        description = defaults.get("description")
        if isinstance(description, str):
            missing["rationale"] = description
    if "m" in flags and "remediation" not in finding and "remediation" not in defaults:
        templates = remediation_templates if isinstance(remediation_templates, dict) else {}
        template = templates.get(finding.get("check_id"))
        summary = template.get("summary") if isinstance(template, dict) else None
        if isinstance(summary, str):
            missing["remediation"] = summary
    if check_frameworks is not None and "frameworks" not in finding:
        missing["frameworks"] = list(check_frameworks.get(finding.get("check_id"), []))
    hydrated = dict(finding, **missing) if missing else finding
    if finding.get("check_id") == "analysis.internet_exposure":
        from peaso.remediation import exposure_action
        return dict(hydrated, remediation=exposure_action(finding.get("evidence"), finding.get("status")))
    return hydrated
