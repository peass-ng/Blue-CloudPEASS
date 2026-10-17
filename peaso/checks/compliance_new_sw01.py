"""Bounded Azure compliance predicates over authoritative scoped snapshots."""
from __future__ import annotations

import re

from . import register, result
from .facts import Unavailable, complete_items, get, guard, list_of_objects


WAF_RULES_ID = "azure_firewall_policy_1_2_8_42_cacbd9e"
WEB_PUBSUB_ID = "azure.gap.web_pub_sub_private_link_used"
GROUP_USER_ID = "azure_directory_user_7_2_4_1_712ef31"
HDINSIGHT_ID = "azure_hdinsight_cluster_1_2_5_11_babfa1b"
IDS = (WAF_RULES_ID, WEB_PUBSUB_ID, GROUP_USER_ID, HDINSIGHT_ID)
PROPOSED_SPEC_SHA256 = {
    WAF_RULES_ID: "af9e659362c7b71b209eba4080f5e6f00b28d613774aba8de69384bbced9c28c",
    WEB_PUBSUB_ID: "82a248e2b678bf88d4b5a78348a6b0d170103fc785e0d5117c835b0e797ef292",
    GROUP_USER_ID: "c7254be816873f2e6d3a763799e47dc55c81c7a4ae5707f6cb8fbffe84861b52",
    HDINSIGHT_ID: "1a79af64d38802aca06a09b640e5502066b071ba7243ea2a948d2ebdfcb8d511",
}
_ARM_ID = re.compile(r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/[^/]+/[^/]+/[^/]+$", re.I)
_UUID = re.compile(r"^[0-9a-fA-F-]{36}$")


def _inventory(item, index, kind, *, directory=False):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("Azure provider authority unavailable")
    scope = get(context, "scope", str)
    if directory:
        if not re.fullmatch(r"/tenants/[^/]+", scope):
            raise Unavailable("tenant scope unavailable")
    elif not re.fullmatch(r"/subscriptions/[0-9a-fA-F-]{36}", scope, re.I):
        raise Unavailable("subscription scope unavailable")
    envelopes = get(index, "collections", dict).get(kind)
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or envelopes[0].get("type") != kind or
            envelopes[0].get("scope", "").casefold() != scope.casefold()):
        raise Unavailable("collection scope authority unavailable")
    rows = complete_items(index, kind)
    declared = get(envelopes[0], "items", list)
    wrappers = get(index, kind, list)
    if ((envelopes[0]["status"] == "empty") != (not rows)
            or len(declared) != len(rows) or len(wrappers) != len(rows)
            or any(get(w, "type", str) != kind or get(w, "scope", str).casefold() != scope.casefold()
                   or get(w, "data", dict) != native
                   for w, native in zip(wrappers, declared))):
        raise Unavailable("scoped inventory and collection disagree")
    identity = get(item, "id", str)
    if directory:
        if not _UUID.fullmatch(identity):
            raise Unavailable("malformed group identity")
    elif not _ARM_ID.fullmatch(identity) or not identity.casefold().startswith(scope.casefold() + "/"):
        raise Unavailable("malformed or foreign ARM identity")
    ids = [get(row, "id", str).casefold() for row in rows]
    if directory:
        if any(not _UUID.fullmatch(value) for value in ids):
            raise Unavailable("foreign or malformed group in tenant inventory")
    elif any(not _ARM_ID.fullmatch(value) or not value.startswith(scope.casefold() + "/") for value in ids):
        raise Unavailable("foreign or malformed ARM resource in inventory")
    if not directory:
        arm_kind = {"web_application_firewall_policy": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
                    "web_pubsub": "Microsoft.SignalRService/webPubSub",
                    "hdinsight_cluster": "Microsoft.HDInsight/clusters"}[kind]
        if any(not re.search(r"/providers/" + re.escape(arm_kind) + r"/[^/]+$", value, re.I) for value in ids):
            raise Unavailable("ARM resource type differs from inventory kind")
    if len(ids) != len(set(ids)) or ids.count(identity.casefold()) != 1 or not any(row == item for row in rows):
        raise Unavailable("resource absent, duplicate, or different from scoped inventory")
    return identity, scope


@register(WAF_RULES_ID, "azure", "network", "web_application_firewall_policy",
          "Configure effective WAF policy rules", "high", "SC-7",
          "Configure at least one custom or managed rule set in each WAF policy and review rule enforcement separately.",
          dependencies=["web_application_firewall_policy"])
def waf_policy_has_rules(item, index):
    rid, _ = _inventory(item, index, "web_application_firewall_policy")
    provenance = get(item, "_provenance", dict)
    if provenance.get("source_operation") != "get" or provenance.get("representation") != "full" or provenance.get("read_only") is not True:
        raise Unavailable("complete WAF policy GET unavailable")
    properties = get(item, "properties", dict)
    custom = properties.get("customRules", [])
    managed = properties.get("managedRules", {})
    if "customRules" in properties or "customRules" in properties.get("_coverage", {}):
        custom = get(properties, "customRules", list)
    if "managedRules" in properties or "managedRules" in properties.get("_coverage", {}):
        managed = get(properties, "managedRules", dict)
    custom = list_of_objects(custom)
    for rule in custom:
        if not get(rule, "name", str):
            raise Unavailable("custom rule identity unavailable")
    sets = managed.get("managedRuleSets", [])
    if "managedRuleSets" in managed or "managedRuleSets" in managed.get("_coverage", {}):
        sets = get(managed, "managedRuleSets", list)
    sets = list_of_objects(sets)
    for rule_set in sets:
        if not get(rule_set, "ruleSetType", str) or not get(rule_set, "ruleSetVersion", str):
            raise Unavailable("managed rule set identity unavailable")
    return result(not (custom or sets), policy_id=rid,
                  custom_rule_count=len(custom), managed_rule_set_count=len(sets),
                  semantics="Structural rule presence; enabled state, mode and effective blocking unassessed")


@register(WEB_PUBSUB_ID, "azure", "network", "web_pubsub",
          "Web PubSub has an approved private endpoint", "medium", "SC-7",
          "Approve a private endpoint connection for each in-scope Web PubSub resource; review public network access separately.",
          dependencies=["web_pubsub"])
def web_pubsub_private_endpoint(item, index):
    rid, _ = _inventory(item, index, "web_pubsub")
    coverage = get(item, "_coverage.privateEndpointConnections", dict)
    if get(coverage, "status", str) not in ("collected", "empty"):
        raise Unavailable("private endpoint connection list incomplete")
    connections = list_of_objects(get(item, "privateEndpointConnections", list))
    if (coverage["status"] == "empty") != (not connections):
        raise Unavailable("contradictory private endpoint coverage")
    approved = []
    seen = set()
    for connection in connections:
        child_id = get(connection, "id", str)
        prefix = rid.rstrip("/") + "/privateEndpointConnections/"
        if (not child_id.casefold().startswith(prefix.casefold()) or not child_id[len(prefix):]
                or "/" in child_id[len(prefix):] or child_id.casefold() in seen):
            raise Unavailable("foreign private endpoint connection")
        seen.add(child_id.casefold())
        status = get(connection, "properties.privateLinkServiceConnectionState.status", str)
        if status not in {"Approved", "Rejected", "Pending", "Disconnected"}:
            raise Unavailable("unrecognized private endpoint connection status")
        if status == "Approved":
            endpoint = get(connection, "properties.privateEndpoint.id", str)
            if (not _ARM_ID.fullmatch(endpoint) or
                    not re.search(r"/providers/Microsoft\.Network/privateEndpoints/[^/]+$", endpoint, re.I)):
                raise Unavailable("private endpoint identity unresolved")
            approved.append(child_id)
    return result(not approved, web_pubsub_id=rid, approved_connections=approved,
                  semantics="Connection approval only; public ingress unassessed")


@register(GROUP_USER_ID, "azure", "hardening", "directory_group",
          "Required Entra groups contain a direct user", "medium", "AC-2",
          "Add an appropriate direct user to each required empty group or review the required-group policy.",
          dependencies=["directory_group", "directory_membership"])
def required_group_has_direct_user(item, index):
    group_id, tenant_scope = _inventory(item, index, "directory_group", directory=True)
    policy = get(index, "context.metadata.compliance_policy", dict)
    if get(policy, "status", str) != "collected" or get(policy, "tenant_id", str) != tenant_scope.removeprefix("/tenants/"):
        raise Unavailable("tenant-bound required-group policy unavailable")
    required = get(policy, "required_group_ids", list)
    if any(not isinstance(value, str) or not _UUID.fullmatch(value) for value in required) or len({x.casefold() for x in required}) != len(required):
        raise Unavailable("required-group policy malformed")
    if not required:
        return "NOT_APPLICABLE", {"reason": "No groups required by complete tenant policy"}
    if group_id.casefold() not in {value.casefold() for value in required}:
        return "NOT_APPLICABLE", {"reason": "Group is outside tenant required-group policy"}
    group_types = get(item, "groupTypes", list)
    if any(not isinstance(value, str) for value in group_types) or "DynamicMembership" in group_types:
        raise Unavailable("dynamic or malformed group membership")
    member_scope = tenant_scope + "/groups/" + group_id
    envelopes = get(index, "collections", dict).get("directory_membership")
    matches = [row for row in envelopes if isinstance(row, dict) and row.get("type") == "directory_membership" and row.get("scope", "").casefold() == member_scope.casefold()] if isinstance(envelopes, list) else []
    if len(matches) != 1 or matches[0].get("status") not in ("collected", "empty"):
        raise Unavailable("group direct-membership page set incomplete")
    members = list_of_objects(matches[0].get("items"))
    seen = set()
    has_user = False
    for member in members:
        mid = get(member, "id", str)
        guard(member)
        mtype = member.get("@odata.type")
        if not isinstance(mtype, str):
            raise Unavailable("direct member OData type unavailable")
        if not _UUID.fullmatch(mid) or mid.casefold() in seen or mtype not in {
                "#microsoft.graph.user", "#microsoft.graph.group", "#microsoft.graph.device",
                "#microsoft.graph.servicePrincipal", "#microsoft.graph.orgContact"}:
            raise Unavailable("direct member identity or type unresolved")
        seen.add(mid.casefold())
        has_user |= mtype == "#microsoft.graph.user"
    if (matches[0]["status"] == "empty") != (not members):
        raise Unavailable("contradictory membership coverage")
    return result(not has_user, group_id=group_id, direct_member_count=len(members),
                  semantics="Direct membership only; transitive membership unassessed")


@register(HDINSIGHT_ID, "azure", "hardening", "hdinsight_cluster",
          "Azure HDInsight clusters have Enterprise Security Package (ESP) with Kerberos authentication enabled", "medium", "IA-2",
          "Configure the HDInsight security profile for an approved Microsoft Entra Domain Services deployment and verify required LDAPS endpoints.",
          dependencies=["hdinsight_cluster"])
def hdinsight_approved_directory(item, index):
    rid, scope = _inventory(item, index, "hdinsight_cluster")
    provenance = get(item, "_provenance", dict)
    if provenance.get("representation") != "full" or provenance.get("source_operation") != "get" or provenance.get("read_only") is not True:
        raise Unavailable("complete HDInsight cluster GET unavailable")
    policy = get(index, "context.metadata.compliance_policy", dict)
    if get(policy, "status", str) != "collected" or get(policy, "subscription_id", str).casefold() != scope.split("/")[-1].casefold():
        raise Unavailable("subscription-bound HDInsight policy unavailable")
    approved = get(policy, "approvedAaddsResourceIds", list)
    ldaps_required = get(policy, "requireLdaps", bool)
    if not approved or any(not isinstance(value, str) or not _ARM_ID.fullmatch(value)
                           or not re.search(r"/providers/Microsoft\.AAD/domainServices/[^/]+$", value, re.I)
                           for value in approved):
        raise Unavailable("approved Entra Domain Services IDs malformed or empty")
    properties = get(item, "properties", dict)
    profile = get(properties, "securityProfile") if "securityProfile" in properties or "securityProfile" in properties.get("_coverage", {}) else None
    if profile is None:
        return result(True, cluster_id=rid, reason="complete GET has no security profile")
    if not isinstance(profile, dict):
        raise Unavailable("security profile malformed")
    directory_type = get(profile, "directoryType", str)
    if directory_type not in ("ActiveDirectory", "None"):
        raise Unavailable("unrecognized HDInsight directory type")
    if directory_type == "None":
        return result(True, cluster_id=rid, reason="directory type is None")
    aadds = get(profile, "aaddsResourceId", str) if "aaddsResourceId" in profile or "aaddsResourceId" in profile.get("_coverage", {}) else ""
    domain = get(profile, "domain", str) if "domain" in profile or "domain" in profile.get("_coverage", {}) else ""
    if not aadds or not domain or not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", domain):
        return result(True, cluster_id=rid, reason="missing or invalid AAD DS identity or domain")
    if not _ARM_ID.fullmatch(aadds) or not re.search(r"/providers/Microsoft\.AAD/domainServices/[^/]+$", aadds, re.I):
        raise Unavailable("AAD DS resource ID malformed")
    if aadds.casefold() not in {value.casefold() for value in approved}:
        return result(True, cluster_id=rid, reason="AAD DS deployment is not approved")
    if ldaps_required:
        urls = get(profile, "ldapsUrls", list)
        if any(not isinstance(url, str) or not re.fullmatch(r"ldaps://[A-Za-z0-9.-]+:636", url, re.I) for url in urls):
            raise Unavailable("LDAPS endpoint metadata malformed")
        if not urls:
            return result(True, cluster_id=rid, reason="required LDAPS endpoints absent")
    return result(False, cluster_id=rid, directory_id=aadds, domain=domain,
                  semantics="Configured directory and policy-approved identifiers; live authentication untested")
