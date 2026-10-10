"""Reviewed upstream references, isolated from executable rules."""
from functools import lru_cache
import json
from pathlib import Path
from copy import deepcopy


@lru_cache(maxsize=1)
def manifest():
    path = Path(__file__).resolve().parent.parent / "rulepacks" / "upstream_manifest.json"
    return json.loads(path.read_text()) if path.exists() else {"checks": [], "sources": []}


@lru_cache(maxsize=1)
def _mappings():
    output = {}
    for row in manifest()["checks"]:
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
    rows = manifest()["checks"]
    return {"native_checks": len(CHECKS), "upstream_total": len(rows), "upstream": dict(Counter(r["disposition"] for r in rows)),
            "supported_upstream": sum(r["disposition"] in ("ported", "merged") for r in rows),
            "limitations": "Pending references are not implemented. Mappings are reference tags, not certification or complete framework coverage."}


def provenance_for(check_id):
    return [{key: row[key] for key in ("check_id", "repository", "source", "revision", "license", "disposition")} for row in _mappings().get(check_id, [])]
