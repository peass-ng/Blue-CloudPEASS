"""Bounded CloudWatch alarm configuration and action correlations."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
import math
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ALARM = re.compile(r"[A-Za-z0-9_.-]{1,255}\Z")
_REFERENCE = re.compile(r'(?:ALARM|OK|INSUFFICIENT_DATA)\("?([^"()]+)"?\)', re.I)
_WINDOW = timedelta(hours=1)
_NAMES = {"PutMetricAlarm", "PutCompositeAlarm", "EnableAlarmActions",
          "DisableAlarmActions", "SetAlarmState"}


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _sns_actions(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list) or len(value) > 5:
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return tuple(sorted(set(value)))


def _sns_only(actions: tuple[str, ...], region: str) -> bool:
    return bool(actions) and all(re.fullmatch(
        r"arn:aws:sns:" + re.escape(region) + r":[0-9]{12}:[A-Za-z0-9_.-]{1,256}", action)
        for action in actions)


def _references(rule: Any, region: str, account: str) -> set[str]:
    if not isinstance(rule, str) or len(rule) > 10240:
        return set()
    result = set()
    prefix = f"arn:aws:cloudwatch:{region}:{account}:alarm:"
    for match in _REFERENCE.finditer(rule):
        name = match.group(1)
        if name.startswith(prefix):
            name = name[len(prefix):]
        if _ALARM.fullmatch(name):
            result.add(name)
    return result


def _event(record: Mapping[str, Any]) -> tuple[datetime, str, str, Mapping[str, Any]] | None:
    response = record.get("responseElements")
    name = record.get("eventName")
    if (record.get("eventSource") != "monitoring.amazonaws.com"
            or not isinstance(name, str) or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or (isinstance(response, Mapping)
                and (response.get("errorCode") or response.get("errorMessage")))
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    when = _when(record.get("eventTime"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or when is None):
        return None
    return when, account, region, request


def _finding(record: Mapping[str, Any], account: str, target: str,
             event_name: str, flag: str, prior: str | None = None) -> dict[str, Any]:
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    result = {
        "cloud.provider": "aws", "event.source": "monitoring.amazonaws.com",
        "event.name": event_name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        flag: True,
    }
    if prior:
        result["correlation_evidence"] = {"prior_event_id": prior}
    return result


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Use only strictly earlier timestamps; same-second writes have unknown order."""
    by_time: dict[datetime, list[tuple[Mapping[str, Any], str, str, Mapping[str, Any]]]] = defaultdict(list)
    for record in records:
        parsed = _event(record)
        if parsed:
            when, account, region, request = parsed
            by_time[when].append((record, account, region, request))

    metric: dict[tuple[str, str, str], tuple[datetime, Mapping[str, Any], str]] = {}
    composite: dict[tuple[str, str, str], tuple[datetime, set[str], str]] = {}
    enabled: dict[tuple[str, str, str], tuple[datetime, bool, str]] = {}
    findings: list[dict[str, Any]] = []
    for when in sorted(by_time):
        group = by_time[when]
        same_second_metric: dict[tuple[str, str, str], int] = defaultdict(int)
        same_second_composite: dict[tuple[str, str, str], int] = defaultdict(int)
        for record, account, region, request in group:
            alarm = request.get("alarmName")
            if not isinstance(alarm, str):
                continue
            key = account, region, alarm
            if record["eventName"] == "PutMetricAlarm":
                same_second_metric[key] += 1
            elif record["eventName"] == "PutCompositeAlarm":
                same_second_composite[key] += 1
        pending_metric: dict[tuple[str, str, str], list[tuple[Mapping[str, Any], str]]] = defaultdict(list)
        pending_composite: dict[tuple[str, str, str], list[tuple[set[str], str]]] = defaultdict(list)
        pending_enabled: dict[tuple[str, str, str], list[tuple[bool, str]]] = defaultdict(list)
        for record, account, region, request in group:
            name = record["eventName"]
            alarm = request.get("alarmName")
            if name in {"EnableAlarmActions", "DisableAlarmActions"}:
                names = request.get("alarmNames")
                if (not isinstance(names, list) or not names
                        or any(not isinstance(item, str) or not _ALARM.fullmatch(item)
                               for item in names)):
                    continue
                for target in names:
                    key = account, region, target
                    pending_enabled[key].append((name == "EnableAlarmActions", record["eventID"]))
                    if name == "EnableAlarmActions":
                        findings.append(_finding(record, account, target,
                            "AlarmActionsEnabled", "request.cloudwatch_alarm_actions_enabled"))
                continue
            if not isinstance(alarm, str) or not _ALARM.fullmatch(alarm):
                continue
            key = account, region, alarm
            if name == "PutMetricAlarm":
                actions = _sns_actions(request.get("alarmActions"))
                threshold = request.get("threshold")
                periods = request.get("evaluationPeriods")
                if (actions is None or isinstance(threshold, bool)
                        or not isinstance(threshold, (int, float))
                        or not math.isfinite(threshold)
                        or type(periods) is not int or periods < 1):
                    continue
                prior = metric.get(key)
                if (prior and same_second_metric[key] == 1
                        and when - prior[0] <= _WINDOW):
                    before, prior_id = prior[1], prior[2]
                    old_actions = _sns_actions(before.get("alarmActions"))
                    old_threshold = before.get("threshold")
                    old_periods = before.get("evaluationPeriods")
                    if (old_actions is not None and old_actions != actions
                            and _sns_only(old_actions, region) and _sns_only(actions, region)):
                        findings.append(_finding(record, account, alarm,
                            "MetricAlarmActionsRedirected",
                            "request.cloudwatch_alarm_actions_redirected", prior_id))
                    if old_actions and not actions:
                        findings.append(_finding(record, account, alarm,
                            "MetricAlarmActionsCleared",
                            "request.cloudwatch_alarm_actions_cleared", prior_id))
                    if (not isinstance(old_threshold, bool)
                            and isinstance(old_threshold, (int, float))
                            and math.isfinite(old_threshold) and old_threshold > 0
                            and type(old_periods) is int and old_periods > 0
                            and threshold >= old_threshold * 5
                            and periods >= old_periods * 2):
                        findings.append(_finding(record, account, alarm,
                            "MetricAlarmSensitivityReduced",
                            "request.cloudwatch_alarm_sensitivity_reduced", prior_id))
                pending_metric[key].append((request, record["eventID"]))
                pending_enabled[key].append((request.get("actionsEnabled") is True,
                                             record["eventID"]))
            elif name == "PutCompositeAlarm":
                refs = _references(request.get("alarmRule"), region, account)
                for other in (refs if same_second_composite[key] == 1 else ()):
                    prior = composite.get((account, region, other))
                    if prior and when - prior[0] <= _WINDOW and alarm in prior[1]:
                        findings.append(_finding(record, account, alarm,
                            "CompositeAlarmMutualCycleRequested",
                            "request.cloudwatch_composite_mutual_cycle", prior[2]))
                        break
                pending_composite[key].append((refs, record["eventID"]))
            elif name == "SetAlarmState" and request.get("stateValue") == "ALARM":
                prior = metric.get(key)
                state = enabled.get(key)
                if (prior and state and when - prior[0] <= _WINDOW
                        and when - state[0] <= _WINDOW
                        and _sns_only(_sns_actions(prior[1].get("alarmActions")) or (), region)
                        and state[1] is True):
                    findings.append(_finding(record, account, alarm,
                        "ForcedAlarmWithSnsAction", "request.cloudwatch_forced_alarm_sns_action",
                        prior[2]))

        # Changes within one CloudTrail second have no trustworthy order.
        for key, values in pending_metric.items():
            if len(values) == 1:
                metric[key] = when, values[0][0], values[0][1]
            else:
                metric.pop(key, None)
        for key, values in pending_composite.items():
            if len(values) == 1:
                composite[key] = when, values[0][0], values[0][1]
            else:
                composite.pop(key, None)
        for key, values in pending_enabled.items():
            if len(values) == 1:
                enabled[key] = when, values[0][0], values[0][1]
            else:
                enabled.pop(key, None)
    return findings
