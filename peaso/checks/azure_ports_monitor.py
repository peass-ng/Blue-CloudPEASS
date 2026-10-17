"""Subscription alert declarations; exact source conditions, no notification probes."""
from . import register, result, unknown
from .facts import get, list_of_objects, Unavailable
from .fixtures import CASES
from .azure_ports_defender import _scope_rows, _non_subscription, _fixture

CHECK_IDS = []
SOURCE_QUERIES = {}
ALERTS = {
    "monitor_log_alert_create_policy_assignment": ("Administrative", "Microsoft.Authorization/policyAssignments/write", None),
    "monitor_log_alert_delete_policy_assignment": ("Administrative", "Microsoft.Authorization/policyAssignments/delete", None),
    "monitor_log_alert_create_update_nsg": ("Administrative", "Microsoft.Network/networkSecurityGroups/write", "microsoft.network/networksecuritygroups"),
    "monitor_log_alert_delete_nsg": ("Administrative", "Microsoft.Network/networkSecurityGroups/delete", "microsoft.network/networksecuritygroups"),
    "monitor_log_alert_create_update_public_ip_address": ("Administrative", "Microsoft.Network/publicIPAddresses/write", "microsoft.network/publicipaddresses"),
    "monitor_log_alert_delete_public_ip_address": ("Administrative", "Microsoft.Network/publicIPAddresses/delete", "microsoft.network/publicipaddresses"),
    "monitor_log_alert_create_update_security_solution": ("Security", "Microsoft.Security/securitySolutions/write", "microsoft.security/securitysolutions"),
    "monitor_log_alert_delete_security_solution": ("Security", "Microsoft.Security/securitySolutions/delete", "microsoft.security/securitysolutions"),
    "monitor_log_alert_create_update_sql_servers_firewall_rule": ("Administrative", "Microsoft.Sql/servers/firewallRules/write", "microsoft.sql/servers/firewallrules"),
    "monitor_log_alert_delete_sql_servers_firewall_rule": ("Administrative", "Microsoft.Sql/servers/firewallRules/delete", "microsoft.sql/servers/firewallrules"),
}


def _matches(item, scope, category, operation, resource_type):
    enabled = get(item, "properties.enabled", bool)
    location = get(item, "location", str)
    scopes = get(item, "properties.scopes", list)
    if any(not isinstance(value, str) for value in scopes):
        raise Unavailable("Malformed alert scope list")
    if not enabled or location.lower() != "global" or scope not in scopes:
        return False
    conditions = list_of_objects(get(item, "properties.condition.allOf", list))
    pairs = set()
    for condition in conditions:
        if "anyOf" in condition:
            # Pinned source queries inspect direct leaf pairs, not anyOf truth.
            list_of_objects(get(condition, "anyOf", list))
            continue
        field = get(condition, "field", str)
        if "equals" in condition:
            value = get(condition, "equals", str)
            pairs.add((field, value))
        elif "containsAny" in condition:
            values = get(condition, "containsAny", list)
            if any(not isinstance(value, str) for value in values):
                raise Unavailable("Malformed alert containsAny condition")
        else:
            raise Unavailable("Malformed activity alert leaf condition")
    if ("category", category) not in pairs:
        return False
    return ("operationName", operation) in pairs or (resource_type is not None and len(conditions) == 2 and ("resourceType", resource_type) in pairs)


def _register(query, spec):
    cid = "azure.port." + query
    CHECK_IDS.append(cid)
    SOURCE_QUERIES[query] = cid
    category, operation, resource_type = spec
    @register(cid, "azure", "hardening", "activity_log_alert", "Subscription declares an enabled global alert for " + operation, "medium", "AU-6",
              "Review the activity-alert declaration and notification destinations; collection does not test delivery or invoke action groups.",
              target="scope", dependencies=["activity_log_alert"])
    def evaluate(item, index):
        if _non_subscription(item):
            return "NOT_APPLICABLE", {"reason": "Activity-log alert predicate requires subscription scope"}
        scope = get(item, "scope", str)
        rows = _scope_rows(item, index, "activity_log_alert")
        matching = [get(row, "id", str) for row in rows if _matches(row, scope, category, operation, resource_type)]
        return result(not matching, matching_alert_ids=matching, operation=operation, category=category,
                      semantics="Pinned direct-leaf/source scope/enablement/global-location declaration; no action-group or effective-event delivery claim")
    alert = {"id": "/subscriptions/sub/resourceGroups/g/providers/Microsoft.Insights/activityLogAlerts/alert", "location": "Global",
             "properties": {"enabled": True, "scopes": ["/subscriptions/sub"], "condition": {"allOf": [{"field": "category", "equals": category}, {"field": "operationName", "equals": operation}]}}}
    CASES[cid] = {"pass": {"scope": "/subscriptions/sub"}, "fail": {"scope": "/subscriptions/sub"},
                  "pass_index": _fixture("activity_log_alert", [alert]), "fail_index": _fixture("activity_log_alert", [], status="empty")}


for _query, _spec in ALERTS.items():
    _register(_query, _spec)
