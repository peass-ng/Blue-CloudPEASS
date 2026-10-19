"""Classify evaluation scope from native inventory contracts, never from finding prose."""
from functools import lru_cache


@lru_cache(maxsize=1)
def aws_global_types():
    # Metadata-only import: no sessions or provider calls are made here.
    from peaso.collectors.aws import GLOBAL_TYPES
    return frozenset(GLOBAL_TYPES)


def explicit_scope(check):
    callback, seen = check.evaluate, set()
    for _ in range(8):
        if callback is None or id(callback) in seen:
            break
        seen.add(id(callback))
        declared = getattr(callback, "evaluation_scope", None)
        if declared in ("aws_account", "aws_region", "tenant"):
            return declared
        callback = getattr(callback, "__wrapped__", None)
    return None


def evaluation_scope(check):
    """All-global dependencies imply an account question, including missing facts."""
    dependencies = tuple(check.dependencies)
    declared = explicit_scope(check)
    if check.provider == "aws" and declared == "aws_region":
        return "aws_region" if check.target == "scope" else "regional_resource"
    if check.provider == "aws" and (declared == "aws_account" or dependencies and set(dependencies) <= aws_global_types()):
        return "aws_account" if check.target == "scope" else "global_resource"
    if check.provider == "aws":
        return "aws_region" if check.target == "scope" else "regional_resource"
    if check.provider == "gcp":
        return "project_folder_or_organization" if check.target == "scope" else "native_resource"
    if check.provider == "azure":
        return ("verified_tenant" if explicit_scope(check) == "tenant" else "subscription") if check.target == "scope" else "native_resource"
    return "cluster_or_namespace" if check.target == "scope" else "native_resource"


def scope_audit(checks):
    """One explicit review row for every active check, suitable for CSV/JSON receipts."""
    return [{"check_id": check.id, "provider": check.provider, "target": check.target,
             "evaluation_scope": evaluation_scope(check), "dependencies": list(check.dependencies),
             "report_group": "check_id", "preserves_member_statuses": True}
            for check in sorted(checks, key=lambda row: (row.provider, row.id))]
