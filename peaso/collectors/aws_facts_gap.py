"""Collector facts for the AWS upstream-gap predicates (``peaso/checks/aws_gap_*``).

Read-only calls only, issued through the shared scan request context (single-flight
cache, retry budget, pagination and max_pages/max_resources bounds):

* ``log_metric_filter``: logs:DescribeMetricFilters per Region, every log group, paginated.
* ``metric_alarm_account_inventory`` (account-global): one row per enabled Region holding
  that Region's metric filters, metric alarms (identity/actions projection only) and SNS
  subscriptions, each with its own read status. Built by ``metric_alarm_rows`` from the
  same cached regional reads; ``aws.global_job`` supplies the Region list.
* ``aws_account_contact_details`` (account-global): account:GetContactInformation plus
  account:GetAlternateContact for BILLING, OPERATIONS and SECURITY. Contact names, e-mail
  addresses and phone numbers are never stored, hashed or returned: only per-contact
  presence flags and the number of distinct normalized values across the contacts.

A denied or failed read keeps its status (``denied``/``unknown``/...); only the documented
``ResourceNotFoundException`` of the Account API means a contact is absent.
"""
from __future__ import annotations

import copy
import re

SPECS = {
    "log_metric_filter": ("logs", "describe_metric_filters", "metricFilters"),
    "aws_account_contact_details": ("account", "get_contact_information", None),
    # Account-global: assembled per Region by ``metric_alarm_rows`` (see aws.global_job).
    "metric_alarm_account_inventory": ("cloudwatch", "describe_alarms", "MetricAlarms"),
}
GLOBAL_TYPES = {"aws_account_contact_details", "metric_alarm_account_inventory"}
NATIVE_IDS = {"log_metric_filter": "id", "aws_account_contact_details": "id", "metric_alarm_account_inventory": "id"}
READ_ACTIONS = {("logs", "describe_metric_filters"), ("account", "get_contact_information"), ("account", "get_alternate_contact"),
                ("cloudwatch", "describe_alarms"), ("sns", "list_subscriptions")}

_OK = ("collected", "empty")
_FILTER = ("metricFilters[].{filterName: filterName, filterPattern: filterPattern, logGroupName: logGroupName, "
           "applyOnTransformedLogs: applyOnTransformedLogs, metricTransformations: metricTransformations[].{metricName: metricName, "
           "metricNamespace: metricNamespace, dimensions: dimensions}}")
ALTERNATE_TYPES = ("BILLING", "OPERATIONS", "SECURITY")


def _result(items, status=None, error=None):
    from .aws import ReadResult
    return ReadResult(items, status or ("collected" if items else "empty"), error)


def _partition(region):
    return "aws-us-gov" if region.startswith("us-gov-") else "aws-cn" if region.startswith("cn-") else "aws"


# --------------------------------------------------------------------------- metric filters
def _metric_filters(requests, session, region, account):
    read = requests.pages(session, "logs", region, "describe_metric_filters", _FILTER)
    output = []
    for item in read.items:
        if not isinstance(item, dict) or not isinstance(item.get("logGroupName"), str) or not isinstance(item.get("filterName"), str):
            continue
        row = {key: value for key, value in item.items() if value is not None}
        # The JMESPath object constructor emits null for omitted optional
        # dimensions. Preserve omission instead of manufacturing a malformed map.
        for transformation in row.get("metricTransformations", []):
            if isinstance(transformation, dict) and transformation.get("dimensions") is None:
                transformation.pop("dimensions", None)
        row["id"] = f"{item['logGroupName']}/{item['filterName']}"
        output.append(row)
    if len(output) != len(read.items) and read.status in _OK:
        return _result(output, "partial" if output else "malformed", {"code": "malformed_metric_filter", "cause_status": "malformed"})
    read.items = output
    return read


def _alarm(item):
    """Metric identity and action projection of one DescribeAlarms MetricAlarm."""
    row = {key: copy.deepcopy(item[key]) for key in ("AlarmArn", "AlarmName", "MetricName", "Namespace", "Dimensions", "ActionsEnabled", "AlarmActions")
           if key in item}
    metrics = []
    for query in item.get("Metrics") or []:
        if not isinstance(query, dict):
            continue
        entry = {key: copy.deepcopy(query[key]) for key in ("Id", "ReturnData", "AccountId") if key in query}
        if "Expression" in query:
            entry["ExpressionPresent"] = True
        stat = query.get("MetricStat")
        if isinstance(stat, dict) and isinstance(stat.get("Metric"), dict):
            entry["Metric"] = {key: copy.deepcopy(stat["Metric"][key]) for key in ("Namespace", "MetricName", "Dimensions") if key in stat["Metric"]}
        metrics.append(entry)
    if "Metrics" in item:
        row["Metrics"] = metrics
    return row


def _listing(read, items):
    output = {"collection_status": read.status, "items": items}
    if read.error:
        output["error"] = {"code": (read.error or {}).get("code")}
    return output


def metric_alarm_rows(regional_job, session, identity, regions):
    """One row per Region: metric filters, metric alarms and SNS subscriptions with their read status."""
    account = identity["Account"]
    rows = []
    for region in regions:
        filters = regional_job(session, identity, region, "log_metric_filter")
        alarms = regional_job(session, identity, region, "cloudwatch_alarm")
        subscriptions = regional_job(session, identity, region, "sns_subscription")
        alarm_items = [_alarm(x) for x in alarms.items if isinstance(x, dict)]
        topics = {action for alarm in alarm_items for action in alarm.get("AlarmActions") or [] if isinstance(action, str) and action.startswith("arn:")}
        subscription_items = [{key: x[key] for key in ("SubscriptionArn", "TopicArn", "Protocol", "id") if key in x}
                              for x in subscriptions.items if isinstance(x, dict) and x.get("TopicArn") in topics]
        rows.append({"id": f"metric-alarm-coverage/{account}/{region}", "SourceRegion": region,
                     "MetricFilters": _listing(filters, copy.deepcopy([x for x in filters.items if isinstance(x, dict)])),
                     "MetricAlarms": _listing(alarms, alarm_items),
                     "Subscriptions": _listing(subscriptions, subscription_items)})
    return _result(rows, "collected" if rows else "empty")


# --------------------------------------------------------------------------- account contacts
def _norm_name(value):
    return " ".join(value.split()).casefold() if isinstance(value, str) and value.strip() else None


def _norm_email(value):
    return value.strip().casefold() if isinstance(value, str) and value.strip() else None


def _norm_phone(value):
    digits = re.sub(r"[^0-9]", "", value) if isinstance(value, str) else ""
    return digits or None


def _contact_details(requests, session, region, account):
    """Presence flags and distinct-value counts only; no contact value leaves this function."""
    partition = _partition(region)
    contacts, names, emails, phones = {}, {}, {}, {}

    def read(label, operation, key, **arguments):
        response = requests.detail(session, "account", region, operation, absent=("ResourceNotFoundException",), **arguments)
        status = response.get("collection_status")
        if status != "collected":
            contacts[label] = {"collection_status": status, **({"absent": True} if response.get("absent") else {}),
                               **({"error": {"code": (response.get("error") or {}).get("code")}} if response.get("error") else {})}
            return
        value = response.get(key)
        if not isinstance(value, dict):
            contacts[label] = {"collection_status": "malformed", "error": {"code": "malformed_contact"}}
            return
        name = _norm_name(value.get("FullName" if label == "PRIMARY" else "Name"))
        phone = _norm_phone(value.get("PhoneNumber"))
        email = None if label == "PRIMARY" else _norm_email(value.get("EmailAddress"))
        contacts[label] = {"collection_status": "collected", "NamePresent": name is not None, "PhonePresent": phone is not None,
                           **({} if label == "PRIMARY" else {"EmailPresent": email is not None})}
        for target, normalized in ((names, name), (phones, phone), (emails, email)):
            if normalized is not None:
                target[label] = normalized

    read("PRIMARY", "get_contact_information", "ContactInformation")
    for contact_type in ALTERNATE_TYPES:
        read(contact_type, "get_alternate_contact", "AlternateContact", AlternateContactType=contact_type)
    item = {"id": "account-contact-details", "Partition": partition, "Contacts": contacts,
            # Distinct normalized values among the collected, present contacts.
            "DistinctNames": len(set(names.values())), "DistinctPhones": len(set(phones.values())),
            "DistinctEmails": len(set(emails.values())),
            "NamesCompared": len(names), "PhonesCompared": len(phones), "EmailsCompared": len(emails)}
    names = emails = phones = None
    return _result([item], "collected")


FETCHERS = {
    "log_metric_filter": _metric_filters,
    "aws_account_contact_details": _contact_details,
}
