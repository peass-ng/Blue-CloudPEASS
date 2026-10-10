"""Reviewed upstream references, isolated from executable rules."""
from functools import lru_cache
import json
from pathlib import Path
from copy import deepcopy
import gzip

PACK = Path(__file__).resolve().parent.parent / "rulepacks"


@lru_cache(maxsize=1)
def _runtime():
    path = PACK / "runtime_metadata.json"
    return json.loads(path.read_text()) if path.exists() else None


@lru_cache(maxsize=1)
def manifest():
    path = PACK / "upstream_manifest.json"
    if path.exists():
        return json.loads(path.read_text())
    compressed = PACK / "upstream_manifest.json.gz"
    return json.loads(gzip.decompress(compressed.read_bytes())) if compressed.exists() else {"checks": [], "sources": []}


@lru_cache(maxsize=1)
def _mappings():
    runtime = _runtime()
    if runtime is not None:
        return runtime["mappings"]
    return raw_mappings(manifest())


def raw_mappings(data):
    output = {}
    for row in data["checks"]:
        if row["disposition"] not in ("ported", "merged"):
            continue
        for native in row.get("native_checks", []):
            output.setdefault(native, []).append(row)
    return output


def mappings_for(check_id, category, control):
    from . import HACKTRICKS, HACKTRICKS_URL
    result = {HACKTRICKS: {"control": category, "reference": HACKTRICKS_URL, "assurance": "thematic"}}
    for row in _mappings().get(check_id, []):
        for mapping in row.get("frameworks", []):
            name = mapping.get("framework_family") or mapping["framework"]
            # Stable family keys; exact declared names/versions stay in control metadata.
            if name.upper().startswith(("NIST-800-53", "NIST 800-53")):
                name = "NIST 800-53"
            elif name.upper() == "SOC2":
                name = "SOC 2"
            elif name.upper() == "PCI":
                name = "PCI DSS"
            elif name.upper() == "NIST-CSF":
                name = "NIST CSF"
            elif name.upper() == "ISO27001":
                name = "ISO 27001"
            entry = result.setdefault(name, {"controls": [], "assurance": "upstream reference mapping; predicate scope may be narrower"})
            control_mapping = deepcopy(mapping)
            if control_mapping not in entry.setdefault("controls", []):
                entry["controls"].append(control_mapping)
    return result


def coverage():
    from collections import Counter
    from . import CHECKS
    runtime = _runtime()
    if runtime is not None:
        return {**deepcopy(runtime["coverage"]), "native_checks": len(CHECKS)}
    rows = manifest()["checks"]
    totals = Counter(r["disposition"] for r in rows)
    return {"native_checks": len(CHECKS), "upstream_total": len(rows), "upstream": {key: totals[key] for key in ("ported", "merged", "rejected", "pending", "out_of_scope")},
            "supported_upstream": sum(r["disposition"] in ("ported", "merged") for r in rows),
            "outside_runtime_provider_scope": sum(not r.get("runtime_provider_supported", True) for r in rows),
            "runtime_scope_upstream_total": sum(r.get("runtime_provider_supported", True) for r in rows),
            "limitations": "Pending references are not implemented. Mappings are reference tags, not certification or complete framework coverage."}


def provenance_for(check_id):
    return [{key: row[key] for key in ("check_id", "repository", "source", "revision", "license", "disposition")} for row in _mappings().get(check_id, [])]


def framework_catalog():
    """Source checklist/version selectors; availability is explicit per entry."""
    runtime = _runtime()
    return deepcopy(runtime["frameworks"]) if runtime is not None else raw_framework_catalog(manifest())


def raw_framework_catalog(data):
    entries = {}
    for row in data["checks"]:
        for mapping in row["frameworks"]:
            key = (row["repository"], row["provider"], mapping["framework_id"])
            entry = entries.setdefault(key, {"id": mapping["framework_id"], "name": mapping["framework"],
                "family": mapping.get("framework_family", mapping["framework"]), "provider": row["provider"],
                "version": mapping.get("declared_version") or mapping["version"], "declared_version": mapping.get("declared_version"),
                "source_revision": row["revision"], "repository": row["repository"], "native_check_ids": set(),
                "source_check_ids": set(), "pending_source_check_ids": set(), "manual_requirement_ids": set(), "rejected_invalid_ids": set()})
            entry["source_check_ids"].add(row["check_id"])
            if row["disposition"] in ("ported", "merged"):
                entry["native_check_ids"].update(row["native_checks"])
            elif row["disposition"] == "pending":
                entry["pending_source_check_ids"].add(row["check_id"])
            elif row["disposition"] == "rejected":
                entry["manual_requirement_ids" if row.get("review_classification") == "manual_attestation" else "rejected_invalid_ids"].add(row["check_id"])
    output = []
    for key, entry in sorted(entries.items()):
        entry["native_check_ids"] = sorted(entry["native_check_ids"])
        entry["supported_native_checks"] = len(entry["native_check_ids"])
        entry["source_checks"] = len(entry.pop("source_check_ids"))
        entry["pending_source_checks"] = len(entry.pop("pending_source_check_ids"))
        entry["manual_requirements"] = len(entry.pop("manual_requirement_ids"))
        entry["rejected_invalid_predicates"] = len(entry.pop("rejected_invalid_ids"))
        entry["status"] = "out_of_scope" if entry["provider"] not in ("aws", "gcp", "azure", "k8s") else "partially_supported" if entry["native_check_ids"] else "pending"
        output.append(entry)
    return output


def runtime_metadata(data):
    from . import CHECKS
    from collections import Counter
    totals = Counter(r["disposition"] for r in data["checks"])
    fields = ("check_id", "repository", "source", "revision", "license", "disposition", "frameworks", "official_docs")
    mappings = {cid: [{key: row[key] for key in fields if key in row} for row in rows] for cid, rows in raw_mappings(data).items()}
    manual = manual_requirements(data)
    return {"schema_version": "1.1", "mappings": mappings, "frameworks": raw_framework_catalog(data), "manual_requirements": manual,
        "coverage": {"native_checks": len(CHECKS), "upstream_total": len(data["checks"]),
            "upstream": {key: totals[key] for key in ("ported", "merged", "rejected", "pending", "out_of_scope")},
            "supported_upstream": totals["ported"] + totals["merged"],
            "manual_requirements": len(manual), "rejected_invalid_predicates": sum(r["disposition"] == "rejected" and r.get("review_classification") != "manual_attestation" for r in data["checks"]),
            "outside_runtime_provider_scope": totals["out_of_scope"], "runtime_scope_upstream_total": len(data["checks"]) - totals["out_of_scope"],
            "limitations": "Unported target references remain pending; other providers are explicitly out of scope. Reference tags are not certification."}}


def manual_requirements(data=None):
    if data is None:
        runtime = _runtime()
        if runtime is not None:
            return deepcopy(runtime.get("manual_requirements", []))
        data = manifest()
    output = []
    for row in data["checks"]:
        if row.get("review_classification") != "manual_attestation":
            continue
        requirement = row["manual_requirement"]
        dependencies = row.get("dependencies", [])
        scope_kinds = sorted({{"aws_account": "account", "gcp_project": "project", "azure_subscription": "subscription",
            "azure_tenant": "tenant", "azuread_tenant": "tenant", "kubernetes_namespace": "namespace"}[kind]
            for kind in dependencies if kind in ("aws_account", "gcp_project", "azure_subscription", "azure_tenant", "azuread_tenant", "kubernetes_namespace")})
        output.append({"id": row["check_id"], "provider": row["provider"], "title": requirement.get("title", row["title"]),
            "question": requirement["question"], "guidance": requirement.get("guidance", row.get("rationale", "")),
            "scope_kinds": requirement.get("scope_kinds", scope_kinds), "source_dependencies": dependencies,
            "status": "MANUAL", "source": row["source"], "revision": row["revision"], "license": row["license"],
            "frameworks": deepcopy(row["frameworks"]), "reason": row["reason"], "automated": False})
    return output
