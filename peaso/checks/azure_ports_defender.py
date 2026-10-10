"""Defender plan predicates with explicit subscription and collection boundaries."""
from . import register, result, unknown
from .facts import get, complete_items, list_of_objects, Unavailable
from .fixtures import CASES

CHECK_IDS = []
SOURCE_QUERIES = {}
PLAN_RULES = {
    "securitycenter_azure_defender_on_for_sqlservervm": "SqlServerVirtualMachines",
    "securitycenter_azure_defender_on_for_appservice": "AppServices",
    "securitycenter_azure_defender_on_for_cosmosdb": "CosmosDbs",
    "securitycenter_azure_defender_on_for_keyvault": "KeyVaults",
    "securitycenter_azure_defender_on_for_opensource_relational_db": "OpenSourceRelationalDatabases",
    "securitycenter_azure_defender_on_for_resource_manager": "Arm",
    "securitycenter_azure_defender_on_for_server": "VirtualMachines",
    "securitycenter_azure_defender_on_for_sqldb": "SqlServers",
    "securitycenter_azure_defender_on_for_storage": "StorageAccounts",
    "securitycenter_azure_defender_on_for_containers": "Containers",
    "security_center_defender_for_api_enabled": "Api",
    "security_center_defender_for_cloudposture_enabled": "CloudPosture",
}


def _scope_rows(item, index, kind):
    scope = get(item, "scope", str).rstrip("/")
    if not scope.startswith("/subscriptions/") or len(scope.split("/")) != 3:
        raise Unavailable("Defender predicate requires an authoritative subscription scope")
    rows = complete_items(index, kind)
    for row in rows:
        rid = get(row, "id", str)
        if not rid.lower().startswith(scope.lower() + "/"):
            raise Unavailable("dependency belongs to another subscription")
    return rows


def _non_subscription(item):
    scope = get(item, "scope", str)
    return scope.startswith("/tenants/") or scope.startswith("/providers/Microsoft.Management/managementGroups/")


def _pricing(item, index):
    result_map = {}
    for row in _scope_rows(item, index, "security_pricing"):
        name = get(row, "name", str)
        if name in result_map:
            raise Unavailable("ambiguous Defender pricing identity")
        result_map[name] = row
    return result_map


def _tier(row):
    tier = get(row, "properties.pricingTier", str)
    if tier not in ("Standard", "Free"):
        raise Unavailable("unrecognized Defender pricing tier")
    return tier


def _fixture(kind, rows, status="collected"):
    return {"collections": {kind: [{"type": kind, "scope": "/subscriptions/sub", "status": status, "items": rows}]},
            kind: [{"data": row} for row in rows]}


def _plan_row(name, tier):
    return {"id": "/subscriptions/sub/providers/Microsoft.Security/pricings/" + name, "name": name, "properties": {"pricingTier": tier}}


def _register_plan(query, plan):
    cid = "azure.port." + query
    CHECK_IDS.append(cid)
    SOURCE_QUERIES[query] = cid
    @register(cid, "azure", "hardening", "security_pricing", "Defender " + plan + " pricing is Standard in the selected subscription", "medium", "SI-4",
              "Review and enable the intended Defender plan where applicable; pricing does not establish complete asset coverage or runtime sensors.",
              target="scope", dependencies=["security_pricing"])
    def evaluate(item, index):
        if _non_subscription(item):
            return "NOT_APPLICABLE", {"reason": "Subscription pricing predicate does not apply to a tenant/management-group anchor"}
        rows = _pricing(item, index)
        if plan not in rows:
            return unknown("Requested plan is absent from a complete pricing response; availability/applicability is not established", plan=plan)
        tier = _tier(rows[plan])
        return result(tier != "Standard", plan=plan, pricing_tier=tier, semantics="Subscription plan configuration only; no asset/sensor/data-plane coverage claim")
    anchor = {"scope": "/subscriptions/sub"}
    CASES[cid] = {"pass": anchor, "fail": anchor,
                  "pass_index": _fixture("security_pricing", [_plan_row(plan, "Standard")]),
                  "fail_index": _fixture("security_pricing", [_plan_row(plan, "Free")])}


for _query, _plan in PLAN_RULES.items():
    _register_plan(_query, _plan)


@register("azure.port.securitycenter_azure_defender_on_for_database", "azure", "hardening", "security_pricing", "All four reviewed database Defender plans are Standard", "medium", "SI-4",
          "Review the SqlServers, SqlServerVirtualMachines, OpenSourceRelationalDatabases and CosmosDbs pricing configurations separately.",
          target="scope", dependencies=["security_pricing"])
def all_databases(item, index):
    if _non_subscription(item):
        return "NOT_APPLICABLE", {"reason": "Database pricing predicate requires subscription scope"}
    rows = _pricing(item, index)
    required = ("CosmosDbs", "OpenSourceRelationalDatabases", "SqlServerVirtualMachines", "SqlServers")
    tiers = {name: _tier(rows[name]) if name in rows else None for name in required}
    return result(any(value != "Standard" for value in tiers.values()), pricing_tiers=tiers,
                  semantics="The pinned aggregate query explicitly alarms absent required plans after its subscription left join; completeness is gated first")
CHECK_IDS.append("azure.port.securitycenter_azure_defender_on_for_database")
SOURCE_QUERIES["securitycenter_azure_defender_on_for_database"] = CHECK_IDS[-1]
_db_plans = ("CosmosDbs", "OpenSourceRelationalDatabases", "SqlServerVirtualMachines", "SqlServers")
CASES[CHECK_IDS[-1]] = {"pass": {"scope": "/subscriptions/sub"}, "fail": {"scope": "/subscriptions/sub"},
                       "pass_index": _fixture("security_pricing", [_plan_row(name, "Standard") for name in _db_plans]),
                       "fail_index": _fixture("security_pricing", [_plan_row(name, "Standard") for name in _db_plans[1:]])}


def _setting_rule(query, name):
    cid = "azure.port." + query
    CHECK_IDS.append(cid)
    SOURCE_QUERIES[query] = cid
    @register(cid, "azure", "hardening", "security_setting", "Defender declares " + name + " integration enabled", "medium", "SI-4",
              "Review the named Defender integration configuration; enabled state does not prove endpoint onboarding or telemetry delivery.",
              target="scope", dependencies=["security_setting"])
    def evaluate(item, index):
        if _non_subscription(item):
            return "NOT_APPLICABLE", {"reason": "Integration configuration requires subscription scope"}
        rows = [row for row in _scope_rows(item, index, "security_setting") if get(row, "name", str) == name]
        if not rows:
            return unknown("Named integration setting is absent; no enabled configuration was observed", setting=name)
        if len(rows) != 1:
            return unknown("Ambiguous integration setting identity", setting=name)
        enabled = get(rows[0], "properties.enabled", bool)
        return result(not enabled, setting=name, enabled=enabled, semantics="Declared integration flag only; reversed upstream reason labels are corrected")
    rid = "/subscriptions/sub/providers/Microsoft.Security/settings/" + name
    CASES[cid] = {"pass": {"scope": "/subscriptions/sub"}, "fail": {"scope": "/subscriptions/sub"},
                  "pass_index": _fixture("security_setting", [{"id": rid, "name": name, "properties": {"enabled": True}}]),
                  "fail_index": _fixture("security_setting", [{"id": rid, "name": name, "properties": {"enabled": False}}])}


_setting_rule("securitycenter_mcas_integration", "MCAS")
_setting_rule("securitycenter_wdatp_integration", "WDATP")


def _required_setting_rule(name):
    cid = "azure.port.defender_required_" + name.lower()
    CHECK_IDS.append(cid)
    @register(cid, "azure", "hardening", "security_setting", "Defender " + name + " setting exists and is enabled", "medium", "SI-4",
              "Review the named integration configuration and service applicability; no integration is enabled by this check.",
              target="scope", dependencies=["security_setting"])
    def evaluate(item, index):
        if _non_subscription(item):
            return "NOT_APPLICABLE", {"reason": "Integration configuration requires subscription scope"}
        rows = [row for row in _scope_rows(item, index, "security_setting") if get(row, "name", str) == name]
        if not rows:
            return result(True, setting=name, observed_count=0, semantics="Pinned Prowler condition explicitly requires this setting after a complete read")
        if len(rows) != 1:
            return unknown("Ambiguous named integration setting")
        enabled = get(rows[0], "properties.enabled", bool)
        return result(not enabled, setting=name, enabled=enabled)
    rid = "/subscriptions/sub/providers/Microsoft.Security/settings/" + name
    CASES[cid] = {"pass": {"scope": "/subscriptions/sub"}, "fail": {"scope": "/subscriptions/sub"},
                  "pass_index": _fixture("security_setting", [{"id": rid, "name": name, "properties": {"enabled": True}}]),
                  "fail_index": _fixture("security_setting", [])}


_required_setting_rule("MCAS")
_required_setting_rule("WDATP")


@register("azure.port.defender_notify_owner_contact", "azure", "hardening", "security_contact", "Defender contact role notifications are On and include Owner", "medium", "IR-6",
          "Review contact role notifications and include Owner when intended; notification delivery is separate.")
def notify_owner_contact(item, index):
    state = get(item, "properties.notificationsByRole.state", str)
    if state not in ("On", "Off"):
        return unknown("Unrecognized role notification state")
    roles = get(item, "properties.notificationsByRole.roles", list)
    if any(not isinstance(role, str) for role in roles):
        return unknown("Malformed role notification list")
    return result(state != "On" or "Owner" not in roles, notification_state=state, roles=roles)
CHECK_IDS.append("azure.port.defender_notify_owner_contact")
CASES[CHECK_IDS[-1]] = {"pass": {"properties": {"notificationsByRole": {"state": "On", "roles": ["Owner"]}}},
                       "fail": {"properties": {"notificationsByRole": {"state": "Off", "roles": ["Owner"]}}}}


@register("azure.port.defender_alert_severity_contact", "azure", "hardening", "security_contact", "Defender contact alert minimum severity is High or lower", "medium", "IR-6",
          "Configure Alert notifications with Low, Medium or High minimum severity; no notification is sent by this check.")
def alert_severity_contact(item, index):
    sources = list_of_objects(get(item, "properties.notificationsSources", list))
    severity = None
    for source in sources:
        if get(source, "sourceType", str) == "Alert":
            value = get(source, "minimalSeverity")
            if value is not None:
                if value not in ("Low", "Medium", "High", "Critical"):
                    return unknown("Unrecognized alert severity")
                severity = value
    return result(severity is None or severity == "Critical", minimal_severity=severity,
                  semantics="Matches the pinned SDK's last non-null Alert severity selection; role-state and delivery are separate")
CHECK_IDS.append("azure.port.defender_alert_severity_contact")
CASES[CHECK_IDS[-1]] = {"pass": {"properties": {"notificationsSources": [{"sourceType": "Alert", "minimalSeverity": "High"}]}},
                       "fail": {"properties": {"notificationsSources": []}}}
