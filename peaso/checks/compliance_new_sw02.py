"""Signed Azure sw02 checks over complete, same-subscription snapshots.

Embedded Firewall Policy groups and VMSS patch assessments use the collector
wave facts. Missing or partial embedded reads never establish a safe configuration.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects


VM_VNET_ID = "azure.gap.compute_vm_attached_with_network"
FIREWALL_HAS_RULES_ID = "azure_firewall_policy_1_2_8_23_59ad733"
FIREWALL_GROUP_RULES_ID = "azure_firewall_policy_1_2_8_24_cc7cb8a"
VMSS_PATCH_ID = "azure.gap.compute_vm_scale_set_system_updates_installed"
MG_DESCENDANT_ID = "azure_management_group_7_2_1_1_af95df1"
IDS = (VM_VNET_ID, FIREWALL_HAS_RULES_ID, FIREWALL_GROUP_RULES_ID, VMSS_PATCH_ID,
       MG_DESCENDANT_ID)
SPEC_SHA256 = {
    VM_VNET_ID: "0a3b74aa472b7e331bb0230fbbef71b5e61e9f659c35d6a16f2e16b0bb2c6bda",
    FIREWALL_HAS_RULES_ID: "2d5acd04c5e345e9622fcc966fc4c16c8924c808ea3b816495dfbf9d3436e17c",
    FIREWALL_GROUP_RULES_ID: "fb7fef2975812a5d28069e1ff3b32ea7740aef79930717e75bf3d090fca7517f",
    VMSS_PATCH_ID: "b46b78955982732e1d6101a8719f54328c85202e00b63ec2c86cdf7a3c77a69e",
    MG_DESCENDANT_ID: "86c29ca5873996326553742c1ab0df7426a27ac52d222a2f128d52ed1c691985",
}

_SUB = re.compile(r"/subscriptions/[^/?#]+\Z", re.I)
_ARM = re.compile(r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/[^/?#]+/[^/?#]+/[^/?#]+(?:/[^/?#]+/[^/?#]+)*\Z", re.I)


def _identity(value, *, prefix=None):
    if not isinstance(value, str) or not _ARM.fullmatch(value):
        raise Unavailable("malformed Azure resource ID")
    if prefix is not None and not value.casefold().startswith(prefix.casefold() + "/"):
        raise Unavailable("foreign Azure child resource ID")
    return value.casefold()


def _inventory(index, kind):
    context = get(index, "context", dict)
    scope = get(context, "scope", str)
    if get(context, "provider", str) != "azure" or not _SUB.fullmatch(scope):
        raise Unavailable("Azure subscription scope unavailable")
    envelopes = get(index, "collections", dict).get(kind)
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or envelopes[0].get("type") != kind or
            envelopes[0].get("scope", "").casefold() != scope.casefold()):
        raise Unavailable("Azure collection scope unavailable")
    rows = complete_items(index, kind)
    native = get(envelopes[0], "items", list)
    wrapped = get(index, kind, list)
    if (envelopes[0]["status"] == "empty") != (not rows):
        raise Unavailable("Azure collection status conflicts with items")
    if (len(rows) != len(native) or len(rows) != len(wrapped) or
            any(not isinstance(w, dict) or w.get("type") != kind or
                str(w.get("scope", "")).casefold() != scope.casefold() or
                w.get("data") != n for w, n in zip(wrapped, native))):
        raise Unavailable("Azure collection and scoped index disagree")
    seen = set()
    arm_kind = {"vm": "Microsoft.Compute/virtualMachines", "nic": "Microsoft.Network/networkInterfaces",
                "vnet": "Microsoft.Network/virtualNetworks", "firewall_policy": "Microsoft.Network/firewallPolicies",
                "vm_scale_set": "Microsoft.Compute/virtualMachineScaleSets"}[kind]
    for row in rows:
        rid = _identity(get(row, "id", str))
        if (not rid.startswith(scope.casefold() + "/") or rid in seen
                or not re.fullmatch(re.escape(scope) + r"/resourceGroups/[^/?#]+/providers/" + re.escape(arm_kind) + r"/[^/?#]+", rid, re.I)):
            raise Unavailable("foreign or duplicate Azure resource")
        seen.add(rid)
    return rows


def _member(item, rows):
    rid = _identity(get(item, "id", str))
    if sum(_identity(get(row, "id", str)) == rid and row == item for row in rows) != 1:
        raise Unavailable("resource is not the unique collected item")
    return rid


def _policy(index, field):
    metadata = get(get(index, "context", dict), "metadata", dict)
    policy = get(metadata, "sw02", dict)
    if get(policy, "status", str) != "collected":
        raise Unavailable("approved Azure policy unavailable")
    return get(policy, field)


@register(VM_VNET_ID, "azure", "hardening", "vm", "Connect VMs only to approved VNets",
          "medium", "CM-6", "Azure portal > Virtual machines > Networking: Move or recreate VM NICs on approved VNet subnets.",
          dependencies=["vm", "nic", "vnet"])
def vm_attached_to_approved_vnet(item, index):
    vms = _inventory(index, "vm")
    vm_id = _member(item, vms)
    nics = {_identity(get(nic, "id", str)): nic for nic in _inventory(index, "nic")}
    vnets = {_identity(get(vnet, "id", str)): vnet for vnet in _inventory(index, "vnet")}
    approved = _policy(index, "approvedVnetIds")
    if not isinstance(approved, list) or not approved:
        raise Unavailable("approved VNet set unavailable")
    approved_ids = {_identity(value) for value in approved}
    if len(approved_ids) != len(approved) or any(not re.fullmatch(
            r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\.Network/virtualNetworks/[^/?#]+", value, re.I)
            for value in approved_ids):
        raise Unavailable("duplicate approved VNet identity")
    references = list_of_objects(get(item, "properties.networkProfile.networkInterfaces", list))
    if not references:
        return "NOT_APPLICABLE", {"vm_id": vm_id, "reason": "Complete VM declaration has no NIC attachment"}
    attached = set()
    observed, uncertain = [], []
    for reference in references:
        try:
            nic_id = _identity(get(reference, "id", str))
            if nic_id in attached or nic_id not in nics:
                raise Unavailable("duplicate or unresolved VM NIC")
            attached.add(nic_id)
            nic = nics[nic_id]
            if _identity(get(nic, "properties.virtualMachine.id", str)) != vm_id:
                raise Unavailable("NIC is not attached to assessed VM")
            configs = list_of_objects(get(nic, "properties.ipConfigurations", list))
            if not configs:
                raise Unavailable("NIC IP configurations unavailable")
            for config in configs:
                subnet = _identity(get(config, "properties.subnet.id", str))
                if not re.fullmatch(r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\.Network/virtualNetworks/[^/?#]+/subnets/[^/?#]+", subnet, re.I):
                    raise Unavailable("NIC subnet is not a direct VNet child")
                marker = "/subnets/"
                if subnet.count(marker) != 1:
                    raise Unavailable("NIC subnet ID malformed")
                vnet_id = subnet.split(marker)[0]
                vnet = vnets.get(vnet_id)
                if vnet is None:
                    raise Unavailable("NIC VNet unresolved")
                known_subnets = list_of_objects(get(vnet, "properties.subnets", list))
                if subnet not in {_identity(get(row, "id", str)) for row in known_subnets}:
                    raise Unavailable("NIC subnet missing from complete VNet")
                observed.append(vnet_id)
        except Unavailable as exc:
            uncertain.append(str(exc))
    unapproved = sorted(set(observed) - approved_ids)
    if unapproved:
        return result(True, vm_id=vm_id, vnet_ids=sorted(set(observed)),
                      unapproved_vnet_ids=unapproved, uncertain_attachments=uncertain)
    if uncertain or not observed:
        return unknown("VM VNet attachment unresolved", vm_id=vm_id, uncertain_attachments=uncertain)
    return result(False, vm_id=vm_id, vnet_ids=sorted(set(observed)), unapproved_vnet_ids=[])


def _firewall_policies(item, index):
    rows = _inventory(index, "firewall_policy")
    rid = _member(item, rows)
    return rid, {_identity(get(row, "id", str)): row for row in rows}


def _groups(policy):
    coverage = get(policy, "_coverage.ruleCollectionGroups.status", str)
    if coverage not in ("collected", "empty"):
        raise Unavailable("Firewall Policy group pages incomplete")
    policy_id = _identity(get(policy, "id", str))
    rows = list_of_objects(get(policy, "ruleCollectionGroups", list))
    if (coverage == "empty") != (not rows):
        raise Unavailable("Firewall Policy group coverage conflicts with rows")
    seen = set()
    for group in rows:
        gid = _identity(get(group, "id", str), prefix=policy_id + "/ruleCollectionGroups")
        if not re.fullmatch(re.escape(policy_id) + r"/rulecollectiongroups/[^/?#]+", gid):
            raise Unavailable("Firewall Policy group is not a direct child")
        provenance = get(group, "_provenance", dict)
        if (gid in seen or get(provenance, "representation", str) != "full" or
                get(provenance, "source_operation", str) != "get_rule_collection_group" or
                get(provenance, "read_only", bool) is not True or
                get(provenance, "parent_policy_id", str).casefold() != policy_id):
            raise Unavailable("duplicate or partial Firewall Policy group")
        seen.add(gid)
    return rows


def _rules(group):
    collections = list_of_objects(get(group, "properties.ruleCollections", list))
    all_rules = []
    for collection in collections:
        kind = get(collection, "ruleCollectionType", str)
        if kind not in ("FirewallPolicyFilterRuleCollection", "FirewallPolicyNatRuleCollection"):
            raise Unavailable("unsupported Firewall Policy collection type")
        rules = list_of_objects(get(collection, "rules", list))
        for rule in rules:
            rule_type = get(rule, "ruleType", str)
            if rule_type not in ({"ApplicationRule", "NetworkRule"} if kind == "FirewallPolicyFilterRuleCollection" else {"NatRule"}):
                raise Unavailable("rule type conflicts with Firewall Policy collection")
            if not get(rule, "name", str):
                raise Unavailable("Firewall Policy rule name unavailable")
            all_rules.append(rule)
    return all_rules


@register(FIREWALL_HAS_RULES_ID, "azure", "network", "firewall_policy",
          "Azure Firewall Policies contain configured rules", "medium", "CM-6",
          "Add a filter or NAT rule collection containing an applicable rule to the policy or its effective base policy.",
          dependencies=["firewall_policy"])
def firewall_policy_has_rules(item, index):
    policy_id, policies = _firewall_policies(item, index)
    current, visited, count = policy_id, set(), 0
    while current:
        if current in visited or current not in policies:
            raise Unavailable("Firewall Policy base ancestry cyclic or unresolved")
        visited.add(current)
        policy = policies[current]
        for group in _groups(policy):
            count += len(_rules(group))
        # The collector normalizes a documented omitted basePolicy to null
        # only after a full policy GET. An absent field here is unresolved.
        base = get(policy, "properties.basePolicy")
        if base is None:
            if (get(policy, "_provenance.representation", str) != "full"
                    or get(policy, "_provenance.source_operation", str) != "get"
                    or get(policy, "_provenance.read_only", bool) is not True):
                raise Unavailable("absent base policy lacks full read-only GET authority")
            current = None
        else:
            current = _identity(get(base, "id", str))
    return result(count == 0, policy_id=policy_id, rule_count=count, ancestry_count=len(visited))


@register(FIREWALL_GROUP_RULES_ID, "azure", "network", "firewall_policy",
          "Firewall Policy contains at least one rule", "medium", "CM-6",
          "In each empty Firewall Policy Rule Collection Group, add the approved filtering rule or remove the unused group after confirming its intended scope.",
          dependencies=["firewall_policy"])
def firewall_policy_groups_have_rules(item, index):
    policy_id, _ = _firewall_policies(item, index)
    groups = _groups(item)
    if not groups:
        return "NOT_APPLICABLE", {"policy_id": policy_id, "reason": "Complete group inventory is empty"}
    empty, uncertain = [], []
    for group in groups:
        try:
            if not _rules(group):
                empty.append(get(group, "id", str))
        except Unavailable:
            uncertain.append(get(group, "id", str))
    if uncertain and not empty:
        return unknown("Firewall Policy group rules unresolved", uncertain_group_ids=uncertain)
    return result(bool(empty), policy_id=policy_id, group_count=len(groups), empty_group_ids=sorted(empty), uncertain_group_ids=uncertain)


def _instant(value):
    if not isinstance(value, str):
        raise Unavailable("patch timestamp malformed")
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("patch timestamp malformed") from exc
    if when.tzinfo is None or when.utcoffset() is None:
        raise Unavailable("patch timestamp lacks timezone")
    return when.astimezone(timezone.utc)


@register(VMSS_PATCH_ID, "azure", "hardening", "vm_scale_set",
          "VM scale set instances have no pending critical or security patches", "medium", "SI-2",
          "Use Azure Update Manager to install Critical and Security patches on affected VMSS instances, then rerun patch assessment.",
          dependencies=["vm_scale_set"])
def vmss_system_updates(item, index):
    vmss_id = _member(item, _inventory(index, "vm_scale_set"))
    if get(item, "_coverage.instances.status", str) not in ("collected", "empty"):
        raise Unavailable("VMSS instance pages incomplete")
    instances = list_of_objects(get(item, "instances", list))
    if (get(item, "_coverage.instances.status", str) == "empty") != (not instances):
        raise Unavailable("VMSS instance coverage conflicts with rows")
    if not instances:
        return "NOT_APPLICABLE", {"vmss_id": vmss_id, "reason": "Complete VMSS instance inventory is empty"}
    age = _policy(index, "maxAssessmentAgeSeconds")
    if type(age) is not int or age <= 0:
        raise Unavailable("patch assessment freshness policy malformed")
    now = _instant(get(get(index, "context", dict), "created_at", str))
    seen, pending, uncertain = set(), [], []
    for instance in instances:
        instance_id = _identity(get(instance, "id", str), prefix=vmss_id + "/virtualMachines")
        if instance_id in seen:
            raise Unavailable("duplicate VMSS instance")
        seen.add(instance_id)
        try:
            patch = get(instance, "patchAssessment", dict)
            if get(patch, "resourceId", str).casefold() != instance_id:
                raise Unavailable("patch summary belongs to another VMSS instance")
            provenance = get(patch, "_provenance", dict)
            if (get(provenance, "source", str) != "ResourceGraph.patchassessmentresources.summary" or
                    get(provenance, "latest", bool) is not True):
                raise Unavailable("latest patch summary provenance unavailable")
            if get(patch, "status", str) != "Succeeded":
                raise Unavailable("patch assessment not successful")
            elapsed = (now - _instant(get(patch, "lastModifiedDateTime", str))).total_seconds()
            if not 0 <= elapsed <= age:
                raise Unavailable("patch assessment stale or future dated")
            counts = get(patch, "availablePatchCountByClassification", dict)
            critical, security = get(counts, "critical", int), get(counts, "security", int)
            if critical < 0 or security < 0:
                raise Unavailable("patch counts malformed")
            if critical or security:
                pending.append(instance_id)
            else:
                errors = get(patch, "errorDetails", list)
                if errors or get(patch, "unresolvedClassification", bool):
                    raise Unavailable("patch assessment has unresolved errors or classification")
        except Unavailable:
            uncertain.append(instance_id)
    if pending:
        return result(True, vmss_id=vmss_id, pending_instance_ids=sorted(pending),
                      uncertain_instance_ids=sorted(uncertain))
    if uncertain:
        return unknown("VMSS patch assessments incomplete or stale", vmss_id=vmss_id,
                       uncertain_instance_ids=sorted(uncertain))
    return result(False, vmss_id=vmss_id, assessed_instance_count=len(seen))


@register(MG_DESCENDANT_ID, "azure", "hardening", "management_group",
          "Subscriptions belong to the expected Management Group", "medium", "AC-2",
          "In Management groups, move the subscription under expectedManagementGroupId and refresh the descendants inventory.",
          target="scope", dependencies=["subscription", "management_group_descendant"])
def subscription_under_master_group(item, index):
    context = get(index, "context", dict)
    scope = get(context, "scope", str)
    if get(context, "provider", str) != "azure" or not _SUB.fullmatch(scope):
        raise Unavailable("subscription scope unavailable")
    if item != context:
        raise Unavailable("scope context differs from evaluation context")
    master = _policy(index, "expectedManagementGroupId")
    if (not isinstance(master, str) or not re.fullmatch(
            r"/providers/Microsoft\.Management/managementGroups/[^/?#]+", master, re.I)):
        raise Unavailable("expected Management Group policy malformed")
    subscriptions = get(index, "collections", dict).get("subscription")
    if (not isinstance(subscriptions, list) or len(subscriptions) != 1 or
            not isinstance(subscriptions[0], dict) or
            subscriptions[0].get("type") != "subscription" or
            subscriptions[0].get("scope", "").casefold() != scope.casefold()):
        raise Unavailable("subscription collection scope unavailable")
    subscription_rows = complete_items(index, "subscription")
    wrapped_subscriptions = get(index, "subscription", list)
    declared_subscriptions = get(subscriptions[0], "items", list)
    if (len(wrapped_subscriptions) != len(declared_subscriptions)
            or any(get(w, "type", str) != "subscription"
                   or get(w, "scope", str).casefold() != scope.casefold()
                   or get(w, "data", dict) != n for w, n in zip(wrapped_subscriptions, declared_subscriptions))):
        raise Unavailable("subscription inventory index disagrees with envelope")
    if len(subscription_rows) != len(get(subscriptions[0], "items", list)) or len(subscription_rows) > 1:
        raise Unavailable("subscription inventory malformed")
    if not subscription_rows:
        if subscriptions[0].get("status") != "empty":
            raise Unavailable("subscription empty status unavailable")
        return "NOT_APPLICABLE", {"scope": scope, "reason": "Complete subscription scope is empty"}
    if subscriptions[0].get("status") != "collected":
        raise Unavailable("subscription inventory status conflicts with item")
    if get(subscription_rows[0], "id", str).casefold() != scope.casefold():
        raise Unavailable("subscription item is foreign to assessed scope")
    descendants = get(index, "collections", dict).get("management_group_descendant")
    if (not isinstance(descendants, list) or len(descendants) != 1 or
            not isinstance(descendants[0], dict) or
            descendants[0].get("type") != "management_group_descendant" or
            descendants[0].get("scope", "").casefold() != scope.casefold()):
        raise Unavailable("Management Group descendants scope unavailable")
    envelope = descendants[0]
    provenance = get(envelope, "_provenance", dict)
    if (get(provenance, "source_operation", str) != "get_descendants" or
            get(provenance, "parent_management_group_id", str).casefold() != master.casefold() or
            get(provenance, "pages_complete", bool) is not True):
        raise Unavailable("Management Group descendants source incomplete")
    rows = complete_items(index, "management_group_descendant")
    if (envelope["status"] == "empty") != (not rows):
        raise Unavailable("Management Group descendant status conflicts with items")
    wrapped = get(index, "management_group_descendant", list)
    if (len(wrapped) != len(rows) or len(get(envelope, "items", list)) != len(rows) or
            any(not isinstance(w, dict) or w.get("type") != "management_group_descendant" or
                str(w.get("scope", "")).casefold() != scope.casefold() or
                w.get("data") != n for w, n in zip(wrapped, rows))):
        raise Unavailable("Management Group descendants index disagrees with collection")
    subscription_name = scope.rsplit("/", 1)[-1]
    seen, subscription_names, present = set(), set(), False
    for row in rows:
        descendant_id = get(row, "id", str)
        name = get(row, "name", str)
        kind = get(row, "type", str)
        if kind.casefold() == "microsoft.management/managementgroups/subscriptions":
            if (not re.fullmatch(r"[^/?#]+", name) or
                    not re.fullmatch(r"(?:/providers/Microsoft\.Management/managementGroups/[^/?#]+)?/subscriptions/" + re.escape(name), descendant_id, re.I)):
                raise Unavailable("Management Group subscription descendant malformed")
            if name.casefold() in subscription_names:
                raise Unavailable("duplicate Management Group subscription descendant")
            subscription_names.add(name.casefold())
        elif kind.casefold() == "microsoft.management/managementgroups":
            if not re.fullmatch(r"/providers/Microsoft\.Management/managementGroups/[^/?#]+", descendant_id, re.I):
                raise Unavailable("Management Group descendant identity malformed")
        else:
            raise Unavailable("Management Group descendant type unsupported")
        key = descendant_id.casefold()
        if key in seen:
            raise Unavailable("duplicate Management Group descendant")
        seen.add(key)
        if kind.casefold().endswith("/subscriptions") and name.casefold() == subscription_name.casefold():
            present = True
    return result(not present, subscription_id=scope, expected_management_group_id=master,
                  descendant_count=len(rows))
