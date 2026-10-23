"""Finish Least Privilege usage evidence once per scan before snapshot storage."""


def least_privilege_selected(provider, request):
    categories = request.get("categories") or []
    if categories:
        return "least_privilege" in categories
    checks = request.get("checks") or []
    if checks:
        from peaso.analysis import ANALYSIS_CHECKS
        return any(c["id"] in checks and c["category"] == "least_privilege"
                   and c.get("provider") in (provider, "all") for c in ANALYSIS_CHECKS)
    if request.get("frameworks"):
        from peaso.engine import _selection, _analysis_selection
        selected, _ = _selection(provider, None, None, request["frameworks"])
        return any(c["category"] == "least_privilege" for c in
                   _analysis_selection(provider, selected, None, request["frameworks"]))
    return True


def enrich_snapshot(snapshot, connector, request, aws_contexts):
    if connector.get("input_mode", "live") != "live":
        return snapshot
    requirements = set(snapshot.get("metadata", {}).get("collection_plan", {}).get("requirements", []))
    provider = snapshot["provider"]
    if not least_privilege_selected(provider, request):
        return snapshot
    if provider == "aws" and "access_analyzer" in requirements and {"iam_user", "iam_role"} & requirements:
        from .aws_iam_usage_extension import enrich_snapshot as aws_enrich
        return aws_enrich(snapshot, aws_contexts)
    if provider == "gcp" and {"iam_policy", "insight"} <= requirements:
        from .gcp_iam_usage_extension import enrich_snapshot as gcp_enrich
        return gcp_enrich(snapshot, connector)
    if provider == "azure" and {"role_assignment", "role_definition"} <= requirements:
        from .azure_iam_usage_extension import enrich_snapshot as azure_enrich
        return azure_enrich(snapshot, connector)
    return snapshot
