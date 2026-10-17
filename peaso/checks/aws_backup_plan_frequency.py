"""Signed admission: aws_nist_backup_plan_min_retention_35_days (AWS Backup plan frequency and 35-day retention).

Source text: the pinned Steampipe aws-compliance control backup_plan_min_retention_35_days and the AWS Config
managed rule backup-plan-min-frequency-and-min-retention-check it quotes. A plan complies when it "has a backup
rule that satisfies the required frequency and retention period", so the quantifier is AT LEAST ONE rule. The
pinned Steampipe query checks only retention, rule by rule. That stricter retention-only reading stays the
separate native aws.c2b.backup.plan_rules_retention_35, and neither check alone completes a requirement.

The organization chooses the required frequency. It is read only from the operator policy that the AWS
collector seals into snapshot metadata (compliance_policy.aws_backup_plan, peaso/collectors/aws_policy.py).
The AWS Config default (1 day) is never assumed. A missing, malformed or non-covering policy is UNKNOWN. The
35-day minimum comes from the control itself, not from a policy default.

AWS Backup documents ScheduleExpression as cron, in UTC unless ScheduleExpressionTimezone is set. The maximum
gap is exact over the full 400-year Gregorian cycle for plain values, lists, ranges and steps on fixed-offset
clocks. These cannot be bounded and stay unresolved: rate(), L/W/#, wrapping ranges, year-limited crons, zones
with DST or rule changes, event-based deletion and continuous (PITR) coverage. Results describe configured
coverage, never observed recovery points or backup job success.
"""
from __future__ import annotations

from datetime import date
from functools import lru_cache
import math
import re

from . import register, result, unknown
from .compliance_new_aws_backup import _authority, _scoped_plans
from .facts import Unavailable, get, list_of_objects, memoized, optional
from .fixtures import CASES

CHECK_ID = "aws_nist_backup_plan_min_retention_35_days"
PROPOSED_SPEC_SHA256 = "e1d4345dbcb805a8189f0402297ca41e1d26f60b4e008e46338de32733c05ef3"
SUPERSEDED_SPEC_SHA256 = "4ce264ac4b21882b2b8f9fd079788122003ed73c2270c894fd57df4cf58bf4b0"
RETENTION_DAYS = 35
MAX_FREQUENCY_HOURS = 31 * 24  # AWS Config managed rule maximum (31 days)
SEMANTICS = "configured schedule and lifecycle coverage only; not observed recovery-point creation or backup job success"

_PLAN_ARN = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):backup:([a-z0-9-]+):([0-9]{12}):(?:backup-plan|plan):[^:/]+$")
_CYCLE_DAYS = 146097
_CYCLE_START = date(2001, 1, 1).toordinal()
_DAY_NAMES = {"SUN": 1, "MON": 2, "TUE": 3, "WED": 4, "THU": 5, "FRI": 6, "SAT": 7}
_MONTH_NAMES = {n: i for i, n in enumerate(("JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"), 1)}
_CRON = re.compile(r"cron\(([^()]+)\)")
_FIXED_OFFSET_ZONES = {"UTC", "Etc/UTC", "Etc/UCT", "UCT", "Etc/Universal", "Universal", "Etc/Zulu", "Zulu", "GMT", "Etc/GMT",
                       "Etc/GMT0", "Etc/GMT+0", "Etc/GMT-0", "GMT0", "GMT+0", "GMT-0", "Etc/Greenwich", "Greenwich"}
_FIXED_OFFSET = re.compile(r"Etc/GMT[+-](?:[1-9]|1[0-2])|Etc/GMT-1[34]")


class Unresolved(Unavailable):
    """A rule fact that is valid in the API but that this evaluator cannot bound."""


def _field(token, low, high, names=None):
    """A cron field as a sorted list of integers; only plain values, lists, ranges and steps are bounded."""
    values = set()
    for part in token.split(","):
        step = 1
        if "/" in part:
            part, raw_step = part.split("/", 1)
            if not raw_step.isdigit() or int(raw_step) < 1:
                raise Unresolved("cron step cannot be bounded")
            step = int(raw_step)
            part = str(low) + "-" + str(high) if part in ("*", "") else part + "-" + str(high) if "-" not in part else part
        if part == "*":
            lo, hi = low, high
        elif "-" in part:
            lo, hi = (_value(x, low, high, names) for x in part.split("-", 1))
            if lo > hi:
                raise Unresolved("wrapping cron range cannot be bounded")
        else:
            lo = hi = _value(part, low, high, names)
        values.update(range(lo, hi + 1, step))
    if not values:
        raise Unresolved("empty cron field")
    return sorted(values)


def _value(text, low, high, names):
    text = text.upper()
    if names and text in names:
        return names[text]
    if not text.isdigit() or not low <= int(text) <= high:
        raise Unresolved("unsupported cron token " + text)
    return int(text)


@lru_cache(maxsize=256)
def max_day_gap(days, months, weekdays):
    """Maximum circular gap in days between consecutive matching days over one full 400-year cycle.

    Streaming single pass: each cache entry is one int, or None when the pattern never matches. Inputs are
    frozen field sets, or None for a '?' day field.
    """
    first = previous = None
    widest = 0
    for ordinal in range(_CYCLE_START, _CYCLE_START + _CYCLE_DAYS):
        day = date.fromordinal(ordinal)
        if day.month in months and (days is None or day.day in days) and (weekdays is None or (day.isoweekday() % 7) + 1 in weekdays):
            if previous is None:
                first = ordinal
            else:
                widest = max(widest, ordinal - previous)
            previous = ordinal
    if first is None:
        return None
    return max(widest, first + _CYCLE_DAYS - previous)


def cron_max_gap_hours(expression):
    """Exact maximum gap (hours) between consecutive runs of a recurring AWS 6-field cron, on its own clock."""
    match = _CRON.fullmatch(expression)
    if not match:
        raise Unresolved("ScheduleExpression is not an AWS cron expression")
    parts = match.group(1).split()
    if len(parts) != 6:
        raise Unresolved("cron must have six fields")
    minute, hour, dom, month, dow, year = parts
    if year != "*":
        raise Unresolved("year-limited cron has no bounded recurrence")
    if (dom == "?") == (dow == "?"):
        raise Unresolved("cron must set exactly one of day-of-month and day-of-week to '?'")
    times = sorted(h * 60 + m for h in _field(hour, 0, 23) for m in _field(minute, 0, 59))
    day_gap = max_day_gap(None if dom == "?" else frozenset(_field(dom, 1, 31)), frozenset(_field(month, 1, 12, _MONTH_NAMES)),
                          None if dow == "?" else frozenset(_field(dow, 1, 7, _DAY_NAMES)))
    if day_gap is None:
        raise Unresolved("cron never matches a calendar day")
    gaps = [b - a for a, b in zip(times, times[1:])]
    gaps.append(day_gap * 1440 + times[0] - times[-1])
    return max(gaps) / 60


def schedule_gap(rule):
    """(maximum gap hours, form) for a cron rule on a fixed UTC offset; otherwise Unresolved."""
    expression = get(rule, "ScheduleExpression", str)
    zone = optional(rule, "ScheduleExpressionTimezone", "UTC", str)
    if zone not in _FIXED_OFFSET_ZONES and not _FIXED_OFFSET.fullmatch(zone):
        raise Unresolved("schedule timezone offset is not fixed; maximum UTC gap is not provable")
    return cron_max_gap_hours(expression), "cron_utc" if zone in ("UTC", "Etc/UTC") else "cron_fixed_offset"


def retention_days(rule):
    """Configured expiry in days; None means the recovery points never expire."""
    lifecycle = optional(rule, "Lifecycle", None, dict)
    if lifecycle is None:
        return None
    if optional(lifecycle, "DeleteAfterEvent", None) is not None:
        raise Unresolved("event-based deletion has no day threshold")
    days = optional(lifecycle, "DeleteAfterDays", None, int)
    if days is not None and days < 1:
        raise Unavailable("invalid DeleteAfterDays")
    return days


def rule_facts(rule, number, required_hours):
    """One rule's frequency and retention verdicts ('meets', 'misses' or 'unresolved') with their evidence."""
    name = rule.get("RuleName")
    facts = {"rule": number, "rule_name": name if isinstance(name, str) else None}
    try:
        gap, form = schedule_gap(rule)
        facts.update(max_gap_hours=gap, schedule_form=form)
        if gap <= required_hours:
            facts["frequency"] = "meets"
        elif optional(rule, "EnableContinuousBackup", False, bool):
            # Continuous (PITR) coverage depends on the selected resource types, which the plan alone does not prove.
            raise Unresolved("continuous backup coverage is not proven by the plan")
        else:
            facts["frequency"] = "misses"
    except Unavailable as exc:
        facts.update(frequency="unresolved", frequency_reason=str(exc))
    try:
        days = retention_days(rule)
        facts.update(retention_days=days, retention="meets" if days is None or days >= RETENTION_DAYS else "misses")
    except Unavailable as exc:
        facts.update(retention="unresolved", retention_reason=str(exc))
    return facts


def required_frequency_hours(index, scope):
    """The operator-declared maximum interval for this account/Region; never a default."""
    body = get(index, "context.metadata.compliance_policy.aws_backup_plan", dict)
    if get(body, "status", str) != "collected" or get(body, "source", str) != "operator-supplied":
        raise Unavailable("operator backup frequency policy not collected")
    if scope not in get(body, "applies_to", list):
        raise Unavailable("operator backup frequency policy does not cover this account/Region")
    hours = get(body, "required_frequency_hours")
    if type(hours) not in (int, float) or not math.isfinite(hours) or not 0 < hours <= MAX_FREQUENCY_HOURS:
        raise Unavailable("operator required_frequency_hours missing or out of range")
    return hours


@register(CHECK_ID, "aws", "hardening", "backup_plan", "Backup plan min frequency and min retention check", "medium", "CP-9",
          "Add or edit a rule in the AWS Backup plan so its schedule creates recovery points at least as often as the "
          "approved interval and its lifecycle keeps them 35 days or longer, and declare that interval as scan policy.",
          dependencies=["backup_plan"])
def backup_plan_frequency_retention_35(item, index):
    arn = get(item, "BackupPlanArn", str)
    account, region, partition = memoized(index, ("aws_backup_scope_authority",), lambda: _authority(index))
    source = _PLAN_ARN.fullmatch(arn)
    if not source or source.group(1) != partition or source.group(2) != region or source.group(3) != account:
        raise Unavailable("backup plan ARN does not match audited regional account scope")
    if memoized(index, ("aws_backup_plans",), lambda: _scoped_plans(index)).get(arn) != item:
        raise Unavailable("backup plan absent from complete scoped inventory")
    detail = get(item, "Plan", dict)
    if get(detail, "collection_status", str) != "collected":
        raise Unavailable("full GetBackupPlan response unavailable")
    if detail.get("BackupPlanArn", arn) != arn or ("BackupPlanId" in item and detail.get("BackupPlanId", item["BackupPlanId"]) != item["BackupPlanId"]):
        raise Unavailable("GetBackupPlan detail identity mismatch")
    if optional(detail, "DeletionDate", None) is not None:
        raise Unavailable("backup plan is deleted")
    scope = account + "/" + region
    hours = required_frequency_hours(index, scope)
    rules = [rule_facts(rule, number, hours) for number, rule in enumerate(list_of_objects(get(detail, "BackupPlan.Rules", list)), 1)]
    qualifying = [facts["rule"] for facts in rules if facts["frequency"] == facts["retention"] == "meets"]
    unresolved = [facts["rule"] for facts in rules if "misses" not in (facts["frequency"], facts["retention"]) and facts["rule"] not in qualifying]
    evidence = {"backup_plan_arn": arn, "scope": scope, "quantifier": "at_least_one_rule", "rules": rules,
                "required_frequency_hours": hours, "frequency_policy_source": "operator-supplied",
                "required_retention_days": RETENTION_DAYS, "qualifying_rules": qualifying,
                "unresolved_rules": unresolved, "semantics": SEMANTICS}
    if qualifying:
        return result(False, **evidence)
    if unresolved:
        return unknown("no rule is proven to qualify and one or more rules cannot be bounded", **evidence)
    return result(True, **evidence)


_ACCOUNT, _REGION = "123456789012", "eu-west-1"
_SCOPE = _ACCOUNT + "/" + _REGION
_ARN = "arn:aws:backup:eu-west-1:123456789012:plan:22222222-2222-2222-2222-222222222222"


def _plan(*rules):
    return {"BackupPlanId": "22222222-2222-2222-2222-222222222222", "BackupPlanArn": _ARN,
            "Plan": {"collection_status": "collected", "BackupPlanArn": _ARN, "BackupPlan": {"Rules": list(rules)}}}


def _rule(schedule, days):
    rule = {"RuleName": "r", "ScheduleExpression": schedule}
    if days is not None:
        rule["Lifecycle"] = {"DeleteAfterDays": days}
    return rule


def _plan_index(row, policy=True):
    metadata = {"caller_identities": [{"Account": _ACCOUNT, "Arn": "arn:aws:sts::123456789012:assumed-role/Audit/peaso-read-only"}]}
    if policy:
        metadata["compliance_policy"] = {"aws_backup_plan": {"status": "collected", "source": "operator-supplied",
            "applies_to": [_SCOPE], "required_frequency_hours": 24}}
    return {"context": {"provider": "aws", "scope": _SCOPE, "Account": _ACCOUNT, "metadata": metadata},
            "collections": {"backup_plan": [{"type": "backup_plan", "scope": _SCOPE, "status": "collected", "items": [row]}]},
            "backup_plan": [{"type": "backup_plan", "scope": _SCOPE, "data": row}]}


_pass = _plan(_rule("cron(0 5 ? * * *)", 7), _rule("cron(0 5 ? * * *)", None))
_fail = _plan(_rule("cron(0 5 ? * * *)", 34), _rule("cron(0 5 ? * MON *)", 90))
_unknown = _plan(_rule("cron(0 5 ? * * *)", 34), _rule("rate(1 day)", 35))
CASES[CHECK_ID] = {"pass": _pass, "pass_index": _plan_index(_pass),
    "fail": _fail, "fail_index": _plan_index(_fail),
    "unknown": _unknown, "unknown_index": _plan_index(_unknown),
    "index": _plan_index(_pass, policy=False)}
