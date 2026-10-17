"""Reviewed AWS service lifecycle boundaries for factual inventory and history.

Entries use exact collected SDK service IDs and resource kinds. A support-end
notice alone is not evidence that an API or an account's resources vanished.
"""
from __future__ import annotations

from datetime import date, datetime, timezone


RETIRED_SERVICES = {
    "mediastore": {
        "name": "AWS Elemental MediaStore",
        "applies_to_service_kinds": ("media_store_container",),
        "end_of_support": date(2025, 11, 12),
        "no_access_after": date(2025, 11, 13),
        "primary_url": "https://docs.aws.amazon.com/general/latest/gr/full_shutdown_services.html",
        "access_url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediastore-container.html",
    },
}


SUPPORT_ENDED_SERVICES = {
    "waf": {
        "name": "AWS WAF Classic (CloudFront)",
        "applies_to_service_kinds": ("waf_web_acl", "waf_rule", "waf_rule_group"),
        "support_end": date(2025, 9, 30),
        "primary_url": "https://docs.aws.amazon.com/waf/latest/developerguide/waf-migrating-from-classic.html",
        "live_api_retirement_proven": False,
    },
    "waf-regional": {
        "name": "AWS WAF Classic Regional",
        "applies_to_service_kinds": ("wafregional_web_acl", "wafregional_rule", "wafregional_rule_group"),
        "support_end": date(2025, 9, 30),
        "primary_url": "https://docs.aws.amazon.com/waf/latest/developerguide/waf-migrating-from-classic.html",
        "live_api_retirement_proven": False,
    },
}


def retirement_state(kind: str, observed_at: datetime) -> str:
    """Return historical, transition, retired, or unknown for an exact kind.

    The documented November 12/13 discrepancy is an unknown transition day;
    it must not create a false operational PASS or FAIL in historical reports.
    """
    entry = next((value for value in RETIRED_SERVICES.values()
        if kind in value["applies_to_service_kinds"]), None)
    if entry is None or not isinstance(observed_at, datetime) or observed_at.tzinfo is None or observed_at.utcoffset() is None:
        return "unknown"
    observed_day = observed_at.astimezone(timezone.utc).date()
    if observed_day < entry["end_of_support"]:
        return "historical"
    if observed_day <= entry["no_access_after"]:
        return "transition"
    return "retired"


def retired_collection_error(kind: str, observed_at: datetime) -> dict | None:
    """Give a no-call reason only when full service shutdown is proven."""
    if retirement_state(kind, observed_at) != "retired":
        return None
    entry = next(value for value in RETIRED_SERVICES.values()
        if kind in value["applies_to_service_kinds"])
    return {
        "code": "retired_service",
        "reason": f"{entry['name']} is in full shutdown; current inventory is not applicable.",
        "service": "mediastore",
        "end_of_support": entry["end_of_support"].isoformat(),
        "no_access_after": entry["no_access_after"].isoformat(),
        "primary_url": entry["primary_url"],
        "access_url": entry["access_url"],
    }
