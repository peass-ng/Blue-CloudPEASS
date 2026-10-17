"""Signed Azure subnet egress and Bot Service CMK checks over scoped facts."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import hashlib
import json
from ipaddress import ip_address, ip_network
import re
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects

SUBNET_ID = "azure.gap.network_subnet_protected_by_firewall"
BOT_ID = "azure.gap.bot_service_encrypted_with_cmk"
SUBNET_SPEC_SHA256 = "dacbcf0058f4471adb9f2f58d690c8e1a6324a516366fa9435b5fbe766cc6a64"
BOT_SPEC_SHA256 = "576b101b111babd627ca77d9aad52922932bf9bbdbd9db4a443c451fa1e89f58"
_SUBSCRIPTION = re.compile(r"/subscriptions/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", re.I)
_ARM_ID = re.compile(r"/subscriptions/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}/resourceGroups/[^/]+/providers/[^/]+/.+", re.I)


def _scope(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("foreign provider context")
    scope = get(context, "scope", str).casefold()
    match = _SUBSCRIPTION.match(scope)
    if match is None or (scope != match.group() and not re.fullmatch(
            re.escape(match.group()) + r"/resourcegroups/[^/]+/providers/microsoft\.network/virtualnetworks/[^/]+", scope)):
        raise Unavailable("Azure subscription or VNet scope unavailable")
    return match.group()


def _evaluation_scope(index):
    _scope(index)
    return get(get(index, "context", dict), "scope", str).casefold()


def _arm_id(value, scope):
    if not isinstance(value, str) or not _ARM_ID.fullmatch(value) or not value.casefold().startswith(scope + "/"):
        raise Unavailable("malformed or foreign ARM identity")
    return value.casefold()


def _inventory(index, kind, *, parent_kind=None):
    scope = _scope(index)
    evaluation_scope = _evaluation_scope(index)
    collections = get(index, "collections", dict)
    envelopes = collections.get(kind)
    if not isinstance(envelopes, list) or not envelopes:
        raise Unavailable("missing scoped collection: " + kind)
    allowed_scopes = set()
    for envelope in envelopes:
        if get(envelope, "type", str) != kind:
            raise Unavailable("mismatched collection kind")
        envelope_scope = get(envelope, "scope", str).casefold()
        if parent_kind is None:
            if envelope_scope != evaluation_scope:
                raise Unavailable("foreign collection scope")
        else:
            _arm_id(envelope_scope, scope)
            if envelope_scope != evaluation_scope or not re.fullmatch(
                    re.escape(scope) + r"/resourcegroups/[^/]+/providers/microsoft\.network/virtualnetworks/[^/]+", envelope_scope):
                raise Unavailable("invalid subnet parent scope")
        if envelope_scope in allowed_scopes:
            raise Unavailable("duplicate collection scope")
        allowed_scopes.add(envelope_scope)
    rows = complete_items(index, kind)
    wrappers = get(index, kind, list)
    if len(wrappers) != len(rows):
        raise Unavailable("collection wrapper count mismatch")
    expected = {}
    for envelope in envelopes:
        envelope_scope = get(envelope, "scope", str).casefold()
        expected[envelope_scope] = list_of_objects(get(envelope, "items", list))
    observed = {envelope_scope: [] for envelope_scope in expected}
    by_id = {}
    for wrapper, row in zip(wrappers, rows):
        if get(wrapper, "type", str) != kind or get(wrapper, "data", dict) != row:
            raise Unavailable("mismatched collection wrapper")
        wrapper_scope = get(wrapper, "scope", str).casefold()
        if wrapper_scope not in allowed_scopes:
            raise Unavailable("foreign resource wrapper scope")
        observed[wrapper_scope].append(row)
        rid = _arm_id(get(row, "id", str), scope)
        if parent_kind is not None:
            prefix = wrapper_scope + "/subnets/"
            if not rid.startswith(prefix) or not rid[len(prefix):] or "/" in rid[len(prefix):]:
                raise Unavailable("subnet does not belong to collection parent")
        if kind == "bot_service" and not re.fullmatch(
                re.escape(scope) + r"/resourcegroups/[^/]+/providers/microsoft\.botservice/botservices/[^/]+", rid):
            raise Unavailable("Bot Service identity malformed")
        if kind == "subnet_effective_route":
            parent = _arm_id(get(row, "subnetId", str), scope)
            if not re.fullmatch(re.escape(scope) + r"/resourcegroups/[^/]+/providers/microsoft\.network/virtualnetworks/[^/]+/subnets/[^/]+", parent):
                raise Unavailable("effective route fact has malformed subnet identity")
            if not rid.startswith(parent + "/providers/peaso/effectiveroutes/"):
                raise Unavailable("effective route fact has foreign subnet identity")
        if kind == "bot_cmk_key":
            bot = _arm_id(get(row, "botId", str), scope)
            prefix = bot + "/providers/peaso/cmkkeys/"
            if not rid.startswith(prefix) or not rid[len(prefix):] or "/" in rid[len(prefix):]:
                raise Unavailable("CMK key resolution identity malformed")
        if rid in by_id:
            raise Unavailable("duplicate resource identity")
        by_id[rid] = row
    if observed != expected:
        raise Unavailable("collection envelope differs from resource wrappers")
    return by_id


def _this_item(item, index, kind, *, parent_kind=None):
    rows = _inventory(index, kind, parent_kind=parent_kind)
    rid = _arm_id(get(item, "id", str), _scope(index))
    if rid not in rows or rows[rid] != item:
        raise Unavailable("resource does not match complete scoped inventory")
    return rid


def _policy(item, *, name):
    policy = get(item, "_policy", dict)
    if get(policy, "source", str) != "approved_policy" or get(policy, "status", str) != "collected":
        raise Unavailable(name + " policy authority unavailable")
    return policy


def _firewalls(index):
    rows = _inventory(index, "approved_firewall")
    ips = {}
    for rid, row in rows.items():
        kind = get(row, "kind", str)
        if kind not in ("AzureFirewall", "SupportedNGFW"):
            raise Unavailable("unsupported firewall kind")
        if kind == "AzureFirewall" and not re.fullmatch(
                re.escape(_scope(index)) + r"/resourcegroups/[^/]+/providers/microsoft\.network/azurefirewalls/[^/]+", rid):
            raise Unavailable("Azure Firewall identity malformed")
        deployed = get(row, "deployed", bool)
        approved = get(row, "approved", bool)
        if get(row, "approvalSource", str) != "approved_policy":
            raise Unavailable("firewall approval authority unavailable")
        addresses = get(row, "privateIpAddresses", list)
        if not addresses or any(not isinstance(v, str) for v in addresses):
            raise Unavailable("firewall private IP inventory unavailable")
        for address in addresses:
            try:
                parsed = ip_address(address)
            except ValueError as exc:
                raise Unavailable("malformed firewall private IP") from exc
            if not parsed.is_private:
                raise Unavailable("firewall next hop is not a private IP")
            if str(parsed) in ips:
                raise Unavailable("ambiguous firewall private IP")
            ips[str(parsed)] = (rid, deployed and approved)
    return ips



def _complete_route_coverage(item, index, fact, subnet_id, nics, routes):
    """Require independently approved full-universe proof for a PASS."""
    if "nicEvidence" in fact:
        raise Unavailable("sampled native NIC routes cannot prove complete subnet protection")
    if len(nics) > 4096 or len(routes) > 4096:
        raise Unavailable("complete route evidence exceeds safe bound")
    policy = _policy(item, name="subnet scope")
    source = get(policy, "routeCoverageSourceId", str)
    if not source or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", source):
        raise Unavailable("independent route coverage authority unavailable")
    coverage = get(fact, "coverage", dict)
    provenance = get(coverage, "_provenance", dict)
    if (get(provenance, "source_operation", str) != "ExternalCompleteSubnetRouting_Read"
            or get(provenance, "source_id", str) != source
            or get(provenance, "read_only", bool) is not True
            or get(provenance, "policy_approved", bool) is not True
            or get(provenance, "complete", bool) is not True):
        raise Unavailable("independent route coverage source unavailable")
    context = get(index, "context", dict)
    captured = get(context, "created_at", str)
    try:
        instant = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("route snapshot time malformed") from exc
    if instant.tzinfo is None or get(provenance, "captured_at", str) != captured or get(fact, "_provenance.captured_at", str) != captured:
        raise Unavailable("route coverage differs from snapshot instant")
    if (get(coverage, "scope_id", str).casefold() != _evaluation_scope(index)
            or get(coverage, "subnet_id", str).casefold() != subnet_id):
        raise Unavailable("route coverage belongs to another scope or subnet")
    covered_nics = get(coverage, "nicIds", list)
    if (len(covered_nics) != len(nics) or any(not isinstance(nic, str) for nic in covered_nics)
            or {nic.casefold() for nic in covered_nics} != set(nics)):
        raise Unavailable("route coverage does not match attached NICs")
    if (get(coverage, "attachedNicInventoryComplete", bool) is not True
            or get(coverage, "activeRouteTablesComplete", bool) is not True
            or get(coverage, "internetDestinationPartitionComplete", bool) is not True):
        raise Unavailable("independent full route coverage unresolved")
    canonical = json.dumps(routes, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if get(coverage, "routeRowsSha256", str) != hashlib.sha256(canonical.encode()).hexdigest():
        raise Unavailable("route coverage does not bind observed route rows")

def _effective_routes(item, index, subnet_id):
    facts = _inventory(index, "subnet_effective_route")
    matching = [row for row in facts.values() if get(row, "subnetId", str).casefold() == subnet_id]
    if len(matching) != 1:
        raise Unavailable("subnet effective route fact missing or ambiguous")
    fact = matching[0]
    if get(fact, "_provenance.source_operation", str) != "networkInterfaces/getEffectiveRouteTable" or get(fact, "_provenance.read_only", bool) is not True:
        raise Unavailable("effective route source unavailable")
    if get(fact, "exhaustiveInternetDestinations", bool) is not True or get(fact, "allAttachedNicsCovered", bool) is not True:
        raise Unavailable("effective route coverage incomplete")
    families = get(fact, "families", list)
    if families not in (["ipv4"], ["ipv4", "ipv6"]):
        raise Unavailable("IPv4 or IPv6 route coverage unresolved")
    if get(fact, "ipv6Enabled", bool) != ("ipv6" in families):
        raise Unavailable("IPv6 coverage conflicts with subnet state")
    nic_ids = get(fact, "nicIds", list)
    if not nic_ids or any(not isinstance(nic, str) for nic in nic_ids):
        raise Unavailable("no representative NIC for effective routes")
    scope = _scope(index)
    normalized = [_arm_id(nic, scope) for nic in nic_ids]
    if len(set(normalized)) != len(normalized):
        raise Unavailable("duplicate representative NIC")
    routes = list_of_objects(get(fact, "internetRoutes", list))
    if not routes:
        raise Unavailable("effective Internet routes unavailable")
    seen_defaults = set()
    seen_prefixes = set()
    parsed_routes = []
    for route in routes:
        nic = _arm_id(get(route, "nicId", str), scope)
        if nic not in normalized:
            raise Unavailable("route from foreign NIC")
        prefix = get(route, "destinationPrefix", str)
        try:
            network = ip_network(prefix, strict=True)
        except ValueError as exc:
            raise Unavailable("malformed effective destination") from exc
        key = nic, str(network)
        if key in seen_prefixes:
            raise Unavailable("ambiguous active route for destination")
        seen_prefixes.add(key)
        family = "ipv4" if network.version == 4 else "ipv6"
        if family not in families or get(route, "internetBound", bool) is not True:
            raise Unavailable("unclassified effective Internet route")
        if network.prefixlen == 0:
            key = nic, family
            if key in seen_defaults:
                raise Unavailable("ambiguous effective default route")
            seen_defaults.add(key)
        parsed_routes.append((route, nic, str(network)))
    if seen_defaults != {(nic, family) for nic in normalized for family in families}:
        raise Unavailable("effective default route missing")
    _complete_route_coverage(item, index, fact, subnet_id, normalized, routes)
    return parsed_routes


def _fully_shadowed(network, routes, nic):
    """Whether more-specific non-Internet routes cover this whole prefix."""
    residual = [network]
    for other, other_nic, other_prefix in routes:
        if other_nic != nic or get(other, "nextHopType", str) == "Internet":
            continue
        candidate = ip_network(other_prefix, strict=False)
        if candidate.version != network.version or candidate.prefixlen <= network.prefixlen:
            continue
        next_residual = []
        for piece in residual:
            if candidate.subnet_of(piece):
                next_residual.extend(piece.address_exclude(candidate))
            elif piece.subnet_of(candidate):
                continue
            else:
                next_residual.append(piece)
        residual = next_residual
        if len(residual) > 4096:
            raise Unavailable("effective route partition exceeds safe bound")
        if not residual:
            return True
    return False


def _direct_internet_counterexample(index, subnet_id):
    """Evaluate one observed public route without claiming complete egress."""
    from peaso.collectors.azure_wave_network_controls import direct_internet_witness
    facts = _inventory(index, "subnet_effective_route")
    matching = [row for row in facts.values() if get(row, "subnetId", str).casefold() == subnet_id]
    if len(matching) != 1:
        raise Unavailable("subnet route fact missing or ambiguous")
    fact = matching[0]
    if "nicEvidence" not in fact:
        return None  # The existing full-universe fact follows its established path.
    provenance = get(fact, "_provenance", dict)
    if (get(provenance, "source_operation", str) != "networkInterfaces/getEffectiveRouteTable" or
            get(provenance, "read_only", bool) is not True or
            get(provenance, "nic_inventory_operation", str) != "get" or
            get(provenance, "vm_attachment_operation", str) != "get"):
        raise Unavailable("native route and attachment provenance unavailable")
    evidence = list_of_objects(get(fact, "nicEvidence", list))
    seen = set()
    bypass = []
    for row in evidence:
        nic = _arm_id(get(row, "nicId", str), _scope(index))
        vm = _arm_id(get(row, "vmId", str), _scope(index))
        if (not re.fullmatch(re.escape(_scope(index)) +
                r"/resourcegroups/[^/]+/providers/microsoft\.network/networkinterfaces/[^/]+", nic) or
                not re.fullmatch(re.escape(_scope(index)) +
                r"/resourcegroups/[^/]+/providers/microsoft\.compute/virtualmachines/[^/]+", vm) or
                nic in seen):
            raise Unavailable("native NIC or VM attachment identity malformed")
        seen.add(nic)
        routes = list_of_objects(get(row, "activeRoutes", list))
        if any(get(route, "nicId", str).casefold() != nic or
               get(route, "sourceOperation", str) != "networkInterfaces/getEffectiveRouteTable"
               for route in routes):
            raise Unavailable("native route belongs to another NIC")
        try:
            witness = direct_internet_witness(routes)
        except ValueError as exc:
            raise Unavailable("native effective route choice unresolved") from exc
        if row.get("directInternetWitness") != witness:
            raise Unavailable("direct Internet witness differs from active routes")
        if witness is not None:
            bypass.append((nic, witness["destinationIp"], witness["selectedPrefix"]))
    if bypass:
        return result(True, subnet_id=subnet_id, bypass_destinations=bypass,
                      semantics="Read-only active NIC route selects Internet for a public destination; no traffic observed")
    return None


@register(SUBNET_ID, "azure", "network", "subnet",
          "Subnet default route points to an approved Azure Firewall", "medium", "SC-7",
          "Route all Internet-bound traffic from each in-scope subnet through the deployed Azure Firewall or approved next-generation firewall, then verify effective routes including IPv6 and more-specific paths.",
          dependencies=["subnet", "subnet_effective_route", "approved_firewall"], allow_incomplete_failure=True)
def subnet_protected_by_firewall(item, index):
    subnet_id = _this_item(item, index, "subnet", parent_kind="vnet")
    policy = _policy(item, name="subnet scope")
    if get(policy, "inScope", bool) is False:
        return "NOT_APPLICABLE", {"subnet_id": subnet_id, "reason": "authoritative policy excludes subnet"}
    counterexample = _direct_internet_counterexample(index, subnet_id)
    if counterexample is not None:
        return counterexample
    routes = _effective_routes(item, index, subnet_id)
    firewalls = _firewalls(index)
    bypass = []
    unresolved = []
    for route, nic, prefix in routes:
        hop = get(route, "nextHopType", str)
        if hop == "VirtualAppliance":
            address = get(route, "nextHopIpAddress", str)
            try:
                address = str(ip_address(address))
            except ValueError as exc:
                raise Unavailable("malformed effective next-hop IP") from exc
            if address not in firewalls:
                # An unrecognized appliance might be an approved NGFW whose
                # identity was not resolved. It cannot prove a bypass.
                unresolved.append((nic, prefix, address))
                continue
            if firewalls[address][1]:
                continue
            bypass.append((nic, prefix, hop))
        elif hop == "Internet":
            if not _fully_shadowed(ip_network(prefix, strict=False), routes, nic):
                bypass.append((nic, prefix, hop))
        elif hop in ("None", "VirtualNetworkGateway", "VirtualNetwork", "VnetLocal"):
            unresolved.append((nic, prefix, hop))
        else:
            raise Unavailable("unrecognized effective next-hop type")
    if bypass:
        return result(True, subnet_id=subnet_id, bypass_routes=bypass,
                      semantics="Complete effective Internet routing on all attached NICs")
    if unresolved:
        return unknown("effective Internet next hop unresolved", subnet_id=subnet_id,
                       unresolved_routes=unresolved)
    return result(False, subnet_id=subnet_id, route_count=len(routes),
                  semantics="Complete effective Internet routing on all attached NICs")


def _key_url(value):
    if not isinstance(value, str) or not value:
        raise Unavailable("CMK key URL unavailable")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".vault.azure.net")
            or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment
            or not re.fullmatch(r"/keys/[^/]+(?:/[^/]+)?", parsed.path)):
        raise Unavailable("malformed Key Vault key URL")
    return value.casefold()


@register(BOT_ID, "azure", "hardening", "bot_service",
          "Use customer-managed encryption where Bot Service supports it", "medium", "SC-28",
          "Azure portal > Azure Bot > Encryption: Set isCmekEnabled=true and cmekKeyVaultUrl to the approved Key Vault key URI.",
          dependencies=["bot_service", "bot_cmk_key"])
def bot_service_encrypted_with_cmk(item, index):
    bot_id = _this_item(item, index, "bot_service")
    policy = _policy(item, name="Bot Service CMK")
    supported = get(policy, "cmkSupported", bool)
    required = get(policy, "cmkRequired", bool)
    if not supported or not required:
        return "NOT_APPLICABLE", {"bot_id": bot_id, "reason": "CMK unsupported or not required by authoritative policy"}
    if (get(item, "_provenance.source_operation", str) != "botServices/get"
            or get(item, "_provenance.read_only", bool) is not True
            or get(item, "_provenance.representation", str) != "full"):
        raise Unavailable("full Bot Service GET unavailable")
    properties = get(item, "properties", dict)
    enabled = get(properties, "isCmekEnabled", bool)
    if enabled is False:
        return result(True, bot_id=bot_id, configured=False)
    if "cmekKeyVaultUrl" not in properties:
        coverage = get(properties, "_coverage.cmekKeyVaultUrl.status", str)
        if coverage == "empty":
            return result(True, bot_id=bot_id, reason="confirmed missing CMK key URL")
        raise Unavailable("CMK key URL omission not confirmed")
    url = get(properties, "cmekKeyVaultUrl", str)
    if url == "":
        return result(True, bot_id=bot_id, reason="empty CMK key URL")
    key_url = _key_url(url)
    keys = _inventory(index, "bot_cmk_key")
    matches = [row for row in keys.values() if get(row, "botId", str).casefold() == bot_id]
    if len(matches) != 1 or _key_url(get(matches[0], "keyUrl", str)) != key_url:
        raise Unavailable("Bot Service CMK key resolution unavailable")
    key = matches[0]
    if get(key, "_provenance.source_operation", str) != "KeyVault/keys/get" or get(key, "_provenance.read_only", bool) is not True:
        raise Unavailable("Key Vault key read unavailable")
    if get(key, "approvalSource", str) != "approved_policy":
        raise Unavailable("CMK approval authority unavailable")
    if get(key, "usable", bool) is not True or get(key, "approved", bool) is not True:
        return unknown("CMK key usability or approval not established", bot_id=bot_id)
    return result(False, bot_id=bot_id, key_url=key_url,
                  semantics="CMK enabled with a usable approved Key Vault key at snapshot time")


# The native register helper predates the signed encryption category.
CHECKS[-1] = replace(CHECKS[-1], category="encryption")
