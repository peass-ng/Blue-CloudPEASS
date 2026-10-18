"""Automatic scan scope; archived evaluators and source references remain resolvable."""
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path


@lru_cache(maxsize=1)
def exclusions():
    """Reviewed mandatory external requirements, never inferred from read failures."""
    document = json.loads(Path(__file__).with_suffix(".json").read_text())
    if document.get("schema_version") != "1.0" or not isinstance(document.get("checks"), dict):
        raise ValueError("Invalid native-only admission manifest")
    for ident, entry in document["checks"].items():
        if (not isinstance(ident, str) or not ident or not isinstance(entry, dict)
                or not all(isinstance(entry.get(key), str) and entry[key].strip()
                           for key in ("reason", "source"))):
            raise ValueError("Invalid native-only exclusion")
    return document["checks"]


def automated_checks(checks):
    excluded = exclusions()
    return [check for check in checks if check.id not in excluded]


def automated_frameworks(rows):
    """Keep source requirement counts; advertise only selectable runtime predicates."""
    excluded = exclusions()
    output = deepcopy(rows)
    for row in output:
        original = row.get("native_check_ids", [])
        if set(original).intersection(excluded):
            row.setdefault("source_supported_native_checks", row.get("supported_native_checks", len(original)))
            row["requirement_counts_scope"] = "reviewed_source_reference"
        row["native_check_ids"] = [ident for ident in original if ident not in excluded]
        row["supported_native_checks"] = len(row["native_check_ids"])
        row["excluded_custom_checks"] = len(set(original).intersection(excluded))
        if row["excluded_custom_checks"]:
            row["status"] = "partially_supported" if row["native_check_ids"] else "pending"
    return output


def scope():
    return {"mode": "provider_read_only", "manual_attestations": False,
            "excluded_custom_controls": len(exclusions())}


def automated_coverage(coverage):
    result = deepcopy(coverage)
    result["registered_native_checks"] = result["native_checks"]
    result["native_checks"] -= len(exclusions())
    result["source_manual_requirements"] = result.get("manual_requirements", 0)
    result["manual_requirements"] = 0
    result["automation_scope"] = scope()
    return result


def automated_inventory_coverage(coverage, checks):
    result = deepcopy(coverage)
    for provider, row in result.items():
        required = {kind for check in checks if check.provider == provider
                    for kind in [check.kind, *check.dependencies]}
        row["unavailable_projections"] = [kind for kind in row["unavailable_projections"] if kind in required]
    return result


def external_inventory_types(provider):
    # Host stat data is an operator import; Kubernetes APIs do not return it.
    return frozenset({"file_metadata"}) if provider == "k8s" else frozenset()


def automated_inventory_types(provider, types):
    return sorted(set(types) - external_inventory_types(provider))
