"""Bounded AMP rule, Alertmanager, retention, and query log management signals."""

from collections.abc import Mapping
from typing import Any


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


_NAMES = {
    "DescribeRuleGroupsNamespace": ("request.amp_rule_file_read", True),
    "PutRuleGroupsNamespace": ("request.amp_rule_file_replaced", False),
    "DescribeAlertManagerDefinition": ("request.amp_alertmanager_read", True),
    "PutAlertManagerDefinition": ("request.amp_alertmanager_replaced", False),
    "UpdateWorkspaceConfiguration": ("request.amp_retention_one_day", False),
    "DeleteQueryLoggingConfiguration": ("request.amp_query_logging_deleted", False),
}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "aps.amazonaws.com" or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not _NAMES[name][1]
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):return None
    workspace = request.get("workspaceId")
    region, account = record.get("awsRegion"), record.get("recipientAccountId")
    identity = _map(record.get("userIdentity"))
    actor = identity.get("arn")
    if (not isinstance(workspace, str) or not workspace
            or not isinstance(region, str) or not region
            or not isinstance(account, str) or len(account) != 12 or not account.isdigit()
            or identity.get("accountId") != account
            or not isinstance(actor, str) or not actor
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    response = _map(record.get("responseElements"))
    if response.get("errorCode") or response.get("errorMessage"):return None
    status = _map(response.get("status"))
    namespace = request.get("name")
    accepted = False
    if name in {"DescribeRuleGroupsNamespace", "DescribeAlertManagerDefinition"}:
        accepted = not response
        if name == "DescribeRuleGroupsNamespace":
            accepted = accepted and isinstance(namespace, str) and bool(namespace)
    elif name in {"PutRuleGroupsNamespace", "PutAlertManagerDefinition"}:
        data = request.get("data")
        accepted = (isinstance(data, str) and bool(data) and len(data) <= 1_000_000
                    and status.get("statusCode") in {"UPDATING", "ACTIVE"})
        if name == "PutRuleGroupsNamespace":
            accepted = accepted and isinstance(namespace, str) and bool(namespace)
            accepted = accepted and response.get("name") == namespace
    elif name == "UpdateWorkspaceConfiguration":
        accepted = (request.get("retentionPeriodInDays") == 1
                    and not isinstance(request.get("retentionPeriodInDays"), bool)
                    and status.get("statusCode") in {"UPDATING", "ACTIVE"})
    elif name == "DeleteQueryLoggingConfiguration":
        accepted = set(response) <= {"Access-Control-Expose-Headers"}
    if not accepted:return None
    flag = _NAMES[name][0]
    target = (f"arn:aws:aps:{region}:{account}:rulegroupsnamespace/{workspace}/{namespace}"
              if name in {"DescribeRuleGroupsNamespace", "PutRuleGroupsNamespace"}
              else f"arn:aws:aps:{region}:{account}:workspace/{workspace}")
    return {"cloud.provider": "aws", "event.source": "aps.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor, "target.id": target,
            flag: True}
