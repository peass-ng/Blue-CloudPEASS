"""Passive, bounded Defender Adaptive Network Hardening metadata for known VMs.

A recommendation is not evidence that a proposed rule was approved or enforced.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re

ARM = 'https://management.azure.com'
KIND = 'adaptive_network_hardening_native'
NATIVE_TYPES = frozenset({KIND})
API_VERSION = '2020-01-01'
MAX_VMS = 1024
MAX_HARDENINGS = 2048
MAX_PAGES = 4096
MAX_RULES = 16384
MAX_NSG_REFS = 32768
_VM = re.compile(r'/subscriptions/[^/?#\x00-\x20]+/resourceGroups/[^/?#\x00-\x20]+/providers/Microsoft\.Compute/virtualMachines/[^/?#\x00-\x20]+', re.I)
_NIC = re.compile(r'/subscriptions/[^/?#\x00-\x20]+/resourceGroups/[^/?#\x00-\x20]+/providers/Microsoft\.Network/networkInterfaces/[^/?#\x00-\x20]+', re.I)
_NSG = re.compile(r'/subscriptions/[^/?#\x00-\x20]+/resourceGroups/[^/?#\x00-\x20]+/providers/Microsoft\.Network/networkSecurityGroups/[^/?#\x00-\x20]+', re.I)
_RULE_FIELDS = ('name', 'direction', 'ipAddresses', 'destinationPort', 'protocols')
MAX_RULE_IPS = 65536


def required_types(wanted):
    return {'vm'} if KIND in wanted else set()


def _arm_id(value, pattern, scope):
    if (not isinstance(value, str) or pattern.fullmatch(value) is None
            or not value.casefold().startswith(scope.casefold() + '/resourcegroups/')):
        raise ValueError('foreign or malformed Adaptive Network Hardening identity')
    return value


def _parents(reader, scope):
    inventories = [item for item in reader.collections if item.get('type') == 'vm'
                   and str(item.get('scope', '')).casefold() == scope.casefold()]
    if len(inventories) != 1 or inventories[0].get('status') not in ('collected', 'empty'):
        raise ValueError('complete VM inventory unavailable for Adaptive Network Hardening')
    vms, seen = [], set()
    for row in inventories[0].get('items', []):
        vm = _arm_id(row.get('id') if isinstance(row, dict) else None, _VM, scope)
        if vm.casefold() in seen:
            raise ValueError('duplicate Adaptive Network Hardening VM identity')
        seen.add(vm.casefold())
        vms.append(vm)
        if len(vms) > MAX_VMS:
            raise ValueError('Adaptive Network Hardening VM limit exceeded')
    return vms


def _time(value):
    if not isinstance(value, str):
        raise ValueError('Adaptive Network Hardening calculation time unavailable')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('Adaptive Network Hardening calculation time malformed') from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError('Adaptive Network Hardening calculation time has no timezone')
    return parsed.astimezone(timezone.utc).isoformat()


def _project(raw, vm, scope, counters, endpoint):
    if not isinstance(raw, dict):
        raise ValueError('Adaptive Network Hardening resource malformed')
    rid = raw.get('id')
    prefix = vm + '/providers/Microsoft.Security/adaptiveNetworkHardenings/'
    if (not isinstance(rid, str) or not rid.casefold().startswith(prefix.casefold())
            or not rid[len(prefix):] or '/' in rid[len(prefix):] or '?' in rid or '#' in rid
            or str(raw.get('type', '')).casefold() != 'microsoft.security/adaptivenetworkhardenings'):
        raise ValueError('foreign or malformed Adaptive Network Hardening child identity')
    if raw.get('name') != rid.rsplit('/', 1)[-1]:
        raise ValueError('Adaptive Network Hardening child name mismatch')
    props = raw.get('properties')
    if not isinstance(props, dict):
        raise ValueError('Adaptive Network Hardening properties unavailable')
    calculated = _time(props.get('rulesCalculationTime'))
    rules = props.get('rules')
    associations = props.get('effectiveNetworkSecurityGroups')
    if not isinstance(rules, list) or not isinstance(associations, list):
        raise ValueError('Adaptive Network Hardening rules or NSG associations unavailable')
    counters['resources'] += 1
    counters['rules'] += len(rules)
    if counters['resources'] > MAX_HARDENINGS or counters['rules'] > MAX_RULES:
        raise ValueError('Adaptive Network Hardening raw resource or rule limit exceeded')
    projected_rules = []
    for rule in rules:
        if not isinstance(rule, dict) or any(key not in rule for key in _RULE_FIELDS):
            raise ValueError('Adaptive Network Hardening rule incomplete')
        name, direction, ips, port, protocols = (rule[key] for key in _RULE_FIELDS)
        counters['rule_ips'] += len(ips) if isinstance(ips, list) else 0
        if counters['rule_ips'] > MAX_RULE_IPS:
            raise ValueError('Adaptive Network Hardening rule IP limit exceeded')
        if (not isinstance(name, str) or not name or len(name) > 256
                or direction not in ('Inbound', 'Outbound')
                or not isinstance(ips, list) or not ips
                or any(not isinstance(ip, str) or not ip or len(ip) > 256 for ip in ips)
                or type(port) is not int or not 0 <= port <= 65535
                or not isinstance(protocols, list) or not protocols
                or any(protocol not in ('TCP', 'UDP') for protocol in protocols)):
            raise ValueError('Adaptive Network Hardening rule malformed')
        projected_rules.append({'name': name, 'direction': direction, 'ipAddresses': list(ips),
                                'destinationPort': port, 'protocols': list(protocols)})
    projected_associations, seen_nics = [], set()
    for entry in associations:
        if not isinstance(entry, dict):
            raise ValueError('Adaptive Network Hardening NSG association malformed')
        nic = _arm_id(entry.get('networkInterface'), _NIC, scope)
        nsids = entry.get('networkSecurityGroups')
        if not isinstance(nsids, list) or nic.casefold() in seen_nics:
            raise ValueError('Adaptive Network Hardening NSG association incomplete or duplicate')
        seen_nics.add(nic.casefold())
        counters['nsg_refs'] += len(nsids) + 1
        if counters['nsg_refs'] > MAX_NSG_REFS:
            raise ValueError('Adaptive Network Hardening NSG reference limit exceeded')
        normalized, seen_nsgs = [], set()
        for value in nsids:
            nsg = _arm_id(value, _NSG, scope)
            if nsg.casefold() in seen_nsgs:
                raise ValueError('duplicate Adaptive Network Hardening NSG identity')
            seen_nsgs.add(nsg.casefold())
            normalized.append(nsg)
        projected_associations.append({'network_interface_id': nic, 'network_security_group_ids': normalized})
    return {'id': rid, 'vm_id': vm, 'name': raw['name'],
            'rules_calculation_time': calculated,
            'recommended_rules': projected_rules,
            'effective_nsg_associations': projected_associations,
            '_provenance': {'source_operation': 'AdaptiveNetworkHardenings_ListByExtendedResource',
                            'api_version': API_VERSION, 'read_only': True,
                            'representation': 'native_recommendation_metadata',
                            'endpoint': endpoint,
                            'observed_at': datetime.now(timezone.utc).isoformat()}}


def collect(reader, request, scopes, wanted):
    """List native recommendations only for VMs in a complete scoped VM roster."""
    if KIND not in wanted:
        return
    jobs = []
    for scope in scopes:
        try:
            vms = _parents(reader, scope)
        except ValueError as exc:
            reader.unavailable(KIND, scope, 'Microsoft.Security', exc)
            continue

        def fetch(scope=scope, vms=vms):
            counters = {'resources': 0, 'rules': 0, 'rule_ips': 0, 'nsg_refs': 0, 'pages': 0}
            seen = set()
            for vm in vms:
                endpoint = ARM + vm + '/providers/Microsoft.Security/adaptiveNetworkHardenings?api-version=' + API_VERSION
                for page in reader.pages(request, endpoint):
                    counters['pages'] += 1
                    if counters['pages'] > MAX_PAGES:
                        raise ValueError('Adaptive Network Hardening page limit exceeded')
                    output = []
                    for raw in page:
                        row = _project(raw, vm, scope, counters, endpoint)
                        if row['id'].casefold() in seen:
                            raise ValueError('duplicate Adaptive Network Hardening child identity')
                        seen.add(row['id'].casefold())
                        output.append(row)
                    yield output
            if not vms:
                yield []
        jobs.append((KIND, scope, 'Microsoft.Security', fetch))
    reader.run(jobs)
