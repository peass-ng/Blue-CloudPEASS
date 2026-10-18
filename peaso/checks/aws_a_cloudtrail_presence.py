"""Different regional and full-account CloudTrail presence policies."""
from . import register, result, unknown
from .facts import get, Unavailable
from .fixtures import CASES
from .aws_a_facts import complete_items, scope_subject, scope_fixture

NATIVE_IDS = []
SUBJECT = {"scope": "123456789012/us-east-1"}
TRAIL = {"TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/inert", "HomeRegion": "us-east-1", "SourceRegion": "us-east-1", "IsMultiRegionTrail": True, "IsOrganizationTrail": False, "Status": {"IsLogging": True}}


@register("aws.a.cloudtrail.region_has_logging", "aws", "hardening", "cloudtrail", "Region has an associated trail with logging enabled",
    "high", "AU-2", "Review absence or stopped logging in each enabled region.", target="scope", dependencies=["cloudtrail"])
def regional_logging(item, index):
    rows = complete_items(index, "cloudtrail", scope_subject(item))
    unavailable = False
    for row in rows:
        try:
            if get(row, "Status.IsLogging", bool):
                return result(False, associated_logging_trail=True, semantics="Regional DescribeTrails includes associated shadow/multi-region trails; no event-category completeness assertion")
        except Unavailable:
            unavailable = True
    if unavailable:
        return unknown("associated trail logging status unavailable")
    return result(True, associated_logging_trail=False)
CASES["aws.a.cloudtrail.region_has_logging"] = {"pass": SUBJECT, "fail": SUBJECT, "missing": {}, "malformed": None,
    "index": scope_fixture("cloudtrail", [TRAIL]), "fail_index": scope_fixture("cloudtrail", [])}
NATIVE_IDS.append("aws.a.cloudtrail.region_has_logging")


@register("aws.a.cloudtrail.account_has_home_logging", "aws", "hardening", "cloudtrail_account_inventory", "Full account has a logging trail observed in its home region",
    "high", "AU-2", "Review all enabled-region trail inventory before asserting account-wide logging absence.", target="scope", dependencies=["cloudtrail_account_inventory"])
def account_logging(item, index):
    rows = complete_items(index, "cloudtrail_account_inventory", scope_subject(item))
    unavailable = False
    for row in rows:
        if get(row, "SourceRegion", str) != get(row, "HomeRegion", str):
            continue
        try:
            if get(row, "Status.IsLogging", bool):
                return result(False, home_logging_trail=True)
        except Unavailable:
            unavailable = True
    if unavailable:
        return unknown("home trail logging status unavailable")
    return result(True, home_logging_trail=False)
CASES["aws.a.cloudtrail.account_has_home_logging"] = {"pass": SUBJECT, "fail": SUBJECT, "missing": {}, "malformed": None,
    "index": scope_fixture("cloudtrail_account_inventory", [TRAIL]), "fail_index": scope_fixture("cloudtrail_account_inventory", [])}
NATIVE_IDS.append("aws.a.cloudtrail.account_has_home_logging")


@register("aws.a.cloudtrail.account_has_logging_multiregion", "aws", "hardening", "cloudtrail_account_inventory", "Full account has a logging multi-region trail or a logging organization multi-region trail",
    "high", "AU-2", "Review multi-region logging and attest organization trail status when its owner visibility is unavailable.", target="scope", dependencies=["cloudtrail_account_inventory"])
def account_multiregion(item, index):
    rows = complete_items(index, "cloudtrail_account_inventory", scope_subject(item))
    unavailable = False
    for row in rows:
        if not get(row, "IsMultiRegionTrail", bool):
            continue
        home = get(row, "SourceRegion", str) == get(row, "HomeRegion", str)
        if not home:
            continue
        try:
            if get(row, "Status.IsLogging", bool):
                # Source home-trail count overrides every joined organization
                # trail row, including unrelated stopped organization trails.
                return result(False, multiregion_logging_home_trail=True)
        except Unavailable:
            unavailable = True
    if unavailable:
        return unknown("home multi-region trail logging status unavailable")
    organizations = [row for row in rows if get(row, "IsOrganizationTrail", bool)]
    if not organizations:
        return result(True, multiregion_logging_trail=False)
    failures, manual = False, False
    for row in organizations:
        if not get(row, "IsMultiRegionTrail", bool):
            failures = True
            continue
        try:
            failures |= not get(row, "Status.IsLogging", bool)
        except Unavailable:
            manual = True
    if failures:
        return result(True, reason="Pinned organization LEFT JOIN emits at least one failing organization-trail row")
    if manual:
        return "MANUAL", {"reason": "Pinned source organization multi-region trail exists but logging status requires owner review"}
    return result(False, organization_multiregion_logging=True)
CASES["aws.a.cloudtrail.account_has_logging_multiregion"] = {"pass": SUBJECT, "fail": SUBJECT, "missing": {}, "malformed": None,
    "index": scope_fixture("cloudtrail_account_inventory", [TRAIL]), "fail_index": scope_fixture("cloudtrail_account_inventory", [])}
NATIVE_IDS.append("aws.a.cloudtrail.account_has_logging_multiregion")
