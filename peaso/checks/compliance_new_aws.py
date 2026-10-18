"""Defensive AWS predicates for individually reviewed signed compliance proposals.

The registry owner imports this module after compiling the verified ledger.
Evaluators inspect a collected snapshot only; no provider client is created here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import register, result, unknown
from .facts import Unavailable, get, list_of_objects, optional
from .fixtures import CASES


def _clock(index):
    value = get(index, "context.created_at", str)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("invalid snapshot clock") from exc
    if parsed.tzinfo is None:
        raise Unavailable("snapshot clock has no time zone")
    return parsed.astimezone(timezone.utc)


def _instant(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Unavailable("invalid certificate expiry") from exc
    else:
        raise Unavailable("certificate expiry unavailable")
    if parsed.tzinfo is None:
        raise Unavailable("certificate expiry has no time zone")
    return parsed.astimezone(timezone.utc)


@register("aws_cloudfront_origin_failover_configured", "aws", "hardening", "cloudfront_distribution",
          "CloudFront origin failover names two existing origins and status codes", "medium", "CP-10",
          "Configure an owner-reviewed origin group with distinct primary and secondary origins and failover status codes.")
def cloudfront_origin_failover(item, index):
    config = get(item, "Config.DistributionConfig", dict)
    origins = get(config, "Origins", dict)
    origin_items = list_of_objects(get(origins, "Items", list)) if get(origins, "Quantity", int) else []
    origin_ids = {get(origin, "Id", str) for origin in origin_items}
    if len(origin_ids) != len(origin_items) or len(origin_items) != get(origins, "Quantity", int):
        return unknown("origin inventory incomplete or duplicate")
    # CloudFront omits OriginGroups entirely when no origin failover is set.
    # An explicit empty marker authenticates that omission; all other present
    # markers and values still pass the normal fact authority check.
    marker_entries = config.get("_coverage", {})
    marker = marker_entries.get("OriginGroups")
    omitted = "OriginGroups" not in config
    empty_omission = omitted and isinstance(marker, dict) and marker.get("status") == "empty"
    groups = ({"Quantity": 0} if omitted and ("OriginGroups" not in marker_entries or empty_omission)
              else get(config, "OriginGroups", dict))
    if not isinstance(groups, dict):
        return unknown("malformed CloudFront origin groups")
    quantity = get(groups, "Quantity", int)
    group_items = list_of_objects(get(groups, "Items", list)) if quantity else []
    if len(group_items) != quantity:
        return unknown("origin group inventory incomplete")
    if not group_items:
        return result(True, origin_group_count=0)
    invalid = []
    for group in group_items:
        members = get(group, "Members", dict)
        member_items = list_of_objects(get(members, "Items", list))
        member_ids = [get(member, "OriginId", str) for member in member_items]
        codes = get(group, "FailoverCriteria.StatusCodes", dict)
        code_items = get(codes, "Items", list) if get(codes, "Quantity", int) else []
        if not isinstance(code_items, list) or any(type(code) is not int for code in code_items):
            return unknown("malformed failover status code list")
        if any(code not in {400, 403, 404, 416, 429, 500, 502, 503, 504} for code in code_items):
            return unknown("unsupported CloudFront failover status code")
        if len(member_items) != get(members, "Quantity", int) or len(code_items) != get(codes, "Quantity", int):
            return unknown("origin group member or status inventory incomplete")
        if len(member_ids) != 2 or len(set(member_ids)) != 2 or not set(member_ids) <= origin_ids or not code_items:
            invalid.append(group.get("Id"))
    return result(bool(invalid), invalid_origin_groups=invalid, origin_group_count=quantity)


@register("aws_config_continuous_inventory", "aws", "hardening", "config_recorder",
          "AWS Config records all supported resources continuously", "medium", "AU-12",
          "Enable the regional Config recorder, all-supported resource recording, and continuous frequency after reviewing recorder cost.")
def config_continuous_inventory(item, index):
    name = get(item, "name", str)
    all_supported = get(item, "recordingGroup.allSupported", bool)
    frequency = get(item, "recordingMode.recordingFrequency", str)
    if frequency not in ("CONTINUOUS", "DAILY"):
        return unknown("unrecognized Config recording frequency", configured=frequency)
    mode = get(item, "recordingMode", dict)
    overrides = mode.get("recordingModeOverrides", [])
    if not isinstance(overrides, list):
        return unknown("malformed Config recording mode overrides")
    override_frequencies = []
    for override in list_of_objects(overrides):
        resource_types = get(override, "resourceTypes", list)
        if not resource_types or any(not isinstance(value, str) or not value for value in resource_types):
            return unknown("malformed Config override resource types")
        override_frequency = get(override, "recordingFrequency", str)
        if override_frequency not in ("CONTINUOUS", "DAILY"):
            return unknown("unrecognized Config override frequency", configured=override_frequency)
        override_frequencies.append(override_frequency)
    statuses = list_of_objects(get(item, "Status.ConfigurationRecordersStatus", list))
    matching = [status for status in statuses if get(status, "name", str) == name]
    if len(matching) != 1:
        return unknown("matching Config recorder status unavailable or duplicated", recorder=name)
    recording = get(matching[0], "recording", bool)
    return result(not (recording and all_supported and frequency == "CONTINUOUS" and
                       all(value == "CONTINUOUS" for value in override_frequencies)),
                  recorder=name, recording=recording, all_supported=all_supported,
                  frequency=frequency, override_frequencies=override_frequencies)


@register("aws_acm_certificate_lifecycle", "aws", "hardening", "acm_certificate",
          "In-use ACM certificate is issued, unexpired, and renewed or renewal eligible", "high", "SC-17",
          "Renew or replace an in-use certificate before expiry and verify that its renewal path is eligible.")
def acm_certificate_lifecycle(item, index):
    certificate = get(item, "Certificate.Certificate", dict)
    in_use = get(certificate, "InUseBy", list)
    if not isinstance(in_use, list) or any(not isinstance(value, str) for value in in_use):
        return unknown("malformed ACM certificate usage")
    if not in_use:
        return "NOT_APPLICABLE", {"reason": "certificate is not in use"}
    status = get(certificate, "Status", str)
    if status not in {"ISSUED", "PENDING_VALIDATION", "INACTIVE", "EXPIRED", "VALIDATION_TIMED_OUT", "REVOKED", "FAILED"}:
        return unknown("unrecognized certificate status", status=status)
    if status != "ISSUED":
        return result(True, status=status, in_use_by_count=len(in_use))
    expiry = _instant(get(certificate, "NotAfter"))
    now = _clock(index)
    if expiry <= now:
        return result(True, status=status, expiry=expiry.isoformat(), in_use_by_count=len(in_use),
                      observation_time=now.isoformat())
    if expiry > now + timedelta(days=30):
        return result(False, status=status, expiry=expiry.isoformat(), in_use_by_count=len(in_use),
                      observation_time=now.isoformat())
    eligible = get(certificate, "RenewalEligibility", str)
    if eligible not in {"ELIGIBLE", "INELIGIBLE"}:
        return unknown("unrecognized renewal eligibility", configured=eligible)
    failed = eligible != "ELIGIBLE"
    return result(failed, status=status, expiry=expiry.isoformat(), renewal_eligibility=eligible,
                  in_use_by_count=len(in_use), observation_time=now.isoformat())


@register("aws_nist_cloudwatch_alarm_action_enabled", "aws", "hardening", "cloudwatch_alarm",
          "CloudWatch alarm actions are enabled and at least one state action exists", "medium", "SI-4",
          "Enable alarm actions and configure at least one approved ALARM, OK or INSUFFICIENT_DATA action.")
def cloudwatch_action_enabled(item, index):
    enabled = get(item, "ActionsEnabled", bool)
    actions = {}
    for field in ("AlarmActions", "OKActions", "InsufficientDataActions"):
        values = get(item, field, list)
        if any(not isinstance(value, str) or not value for value in values):
            return unknown("malformed CloudWatch alarm state action", field=field)
        actions[field] = values
    return result(not (enabled and any(actions.values())), actions_enabled=enabled,
                  state_actions={field: len(values) for field, values in actions.items()})


@register("aws_config_recorder_all_supported_resources", "aws", "hardening", "config_recorder",
          "AWS Config recorder includes all supported resource types", "medium", "AU-12",
          "Review recording costs and configure all-supported resource coverage without exclusions.")
def config_all_supported_resources(item, index):
    group = get(item, "recordingGroup", dict)
    all_supported = get(group, "allSupported", bool)
    strategy = optional(group, "recordingStrategy", None, dict)
    if strategy is None:
        return result(not all_supported, all_supported=all_supported, strategy="legacy_all_supported_flag")
    if not isinstance(strategy, dict):
        return unknown("malformed Config recording strategy")
    mode = get(strategy, "useOnly", str)
    if mode == "EXCLUSION_BY_RESOURCE_TYPES":
        excluded = get(group, "exclusionByResourceTypes.resourceTypes", list)
        if any(not isinstance(value, str) or not value for value in excluded):
            return unknown("malformed excluded resource type")
        return result(bool(excluded), strategy=mode, excluded_resource_types=excluded)
    if mode == "ALL_SUPPORTED_RESOURCE_TYPES":
        if not all_supported:
            return unknown("contradictory all-supported Config recording fields")
        return result(False, strategy=mode, all_supported=True)
    if mode == "INCLUSION_BY_RESOURCE_TYPES":
        return result(True, strategy=mode, all_supported=all_supported)
    return unknown("unrecognized Config recording strategy", strategy=mode)


# Independent, provider-shaped aggregate behavior fixtures. The detailed
# semantic tests cover additional boundaries and incomplete inventories.
_origins = {"Quantity": 2, "Items": [{"Id": "primary"}, {"Id": "secondary"}]}
_group = {"Id": "failover", "Members": {"Quantity": 2, "Items": [
    {"OriginId": "primary"}, {"OriginId": "secondary"}]},
    "FailoverCriteria": {"StatusCodes": {"Quantity": 1, "Items": [503]}}}
CASES["aws_cloudfront_origin_failover_configured"] = {
    "pass": {"Config": {"DistributionConfig": {"Origins": _origins,
        "OriginGroups": {"Quantity": 1, "Items": [_group]}}}},
    "fail": {"Config": {"DistributionConfig": {"Origins": _origins,
        "OriginGroups": {"Quantity": 0}}}},
    "unknown": {"Config": {"DistributionConfig": {"Origins": _origins,
        "OriginGroups": {"Quantity": 2, "Items": [_group]}}}},
}
_recorder = {"name": "default", "recordingGroup": {"allSupported": True},
    "recordingMode": {"recordingFrequency": "CONTINUOUS"},
    "Status": {"ConfigurationRecordersStatus": [{"name": "default", "recording": True}]}}
CASES["aws_config_continuous_inventory"] = {
    "pass": _recorder,
    "fail": {**_recorder, "recordingMode": {"recordingFrequency": "DAILY"}},
    "unknown": {**_recorder, "Status": {"collection_status": "denied"}},
}
_certificate = {"Certificate": {"Certificate": {"Status": "ISSUED",
    "NotAfter": "2026-11-20T00:00:00Z", "InUseBy": [
        "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/inert"]}}}
CASES["aws_acm_certificate_lifecycle"] = {
    "pass": _certificate,
    "fail": {"Certificate": {"Certificate": {**_certificate["Certificate"]["Certificate"],
        "NotAfter": "2026-10-11T00:00:00Z"}}},
    "unknown": {"Certificate": {"collection_status": "denied"}},
    "index": {"context": {"created_at": "2026-10-12T00:00:00Z"}},
}
_alarm = {"ActionsEnabled": True, "AlarmActions": [],
    "OKActions": ["arn:aws:sns:us-east-1:111122223333:alerts"],
    "InsufficientDataActions": []}
CASES["aws_nist_cloudwatch_alarm_action_enabled"] = {
    "pass": _alarm, "fail": {**_alarm, "ActionsEnabled": False},
    "unknown": {**_alarm, "AlarmActions": "malformed"},
}
CASES["aws_config_recorder_all_supported_resources"] = {
    "pass": {"recordingGroup": {"allSupported": True}},
    "fail": {"recordingGroup": {"allSupported": False,
        "resourceTypes": ["AWS::EC2::Instance"]}},
    "unknown": {"recordingGroup": {"allSupported": True,
        "recordingStrategy": {"useOnly": "FUTURE"}}},
}
