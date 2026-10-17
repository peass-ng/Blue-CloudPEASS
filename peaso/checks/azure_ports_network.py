"""Reviewed network baselines with exact ARM identity and inventory boundaries."""
from . import register, result, unknown
from .facts import get, complete_items, Unavailable
from .fixtures import CASES
from .azure_ports_defender import _scope_rows, _non_subscription, _fixture

CHECK_IDS = []
SOURCE_QUERIES = {}
SUB = '/subscriptions/sub'
NSG_ID = SUB + '/resourceGroups/group/providers/Microsoft.Network/networkSecurityGroups/nsg'
VNET_ID = SUB + '/resourceGroups/group/providers/Microsoft.Network/virtualNetworks/vnet'
FLOW_ID = SUB + '/resourceGroups/group/providers/Microsoft.Network/networkWatchers/watcher/flowLogs/log'


def port(query, kind, title, *, target='resource', dependencies=None, severity='medium'):
    cid = 'azure.port.' + query
    CHECK_IDS.append(cid); SOURCE_QUERIES[query] = cid
    return register(cid, 'azure', 'hardening', kind, title, severity, 'AU-11' if 'flowlog' in query or 'flow_log' in query else 'AC-17',
                    'Review the declared network metadata and existing configuration; this check performs no network probe, deployment or modification.',
                    target=target, dependencies=dependencies or [kind])


@port('network_bastion_host_min_1', 'bastion_host', 'Selected subscription has at least one Bastion host', target='scope', dependencies=['bastion_host'], severity='low')
def bastion(item, index):
    if _non_subscription(item):
        return 'NOT_APPLICABLE', {'reason': 'Bastion presence requires subscription scope'}
    hosts = _scope_rows(item, index, 'bastion_host')
    return result(not hosts, host_count=len(hosts), semantics='Subscription host presence only; reachability and subnet/workload coverage are separate')
CASES[SOURCE_QUERIES['network_bastion_host_min_1']] = {'pass': {'scope': SUB}, 'fail': {'scope': SUB}, 'pass_index': _fixture('bastion_host', [{'id': SUB + '/resourceGroups/group/providers/Microsoft.Network/bastionHosts/host'}]), 'fail_index': _fixture('bastion_host', [], 'empty')}


@port('network_sg_flowlog_retention_period_greater_than_90', 'nsg', 'Existing NSG flow-log declaration is enabled and retention days are at least 90', dependencies=['nsg', 'flow_log'])
def nsg_retention(item, index):
    rid = get(item, 'id', str)
    if not rid.lower().startswith('/subscriptions/') or '/providers/microsoft.network/networksecuritygroups/' not in rid.lower():
        raise Unavailable('Malformed NSG ARM identity')
    rows = complete_items(index, 'flow_log')
    matches = [row for row in rows if get(row, 'properties.targetResourceId', str).casefold() == rid.casefold()]
    if not matches:
        return result(True, matching_log_count=0, semantics='Pinned source explicitly alarms absence after its left join; complete inventory required')
    failed = []
    for row in matches:
        enabled = get(row, 'properties.enabled', bool)
        days = get(row, 'properties.retentionPolicy.days', int)
        if days < 0:
            raise Unavailable('Malformed negative flow-log retention')
        if not enabled or days < 90:
            failed.append(get(row, 'id', str))
    return result(bool(failed), failing_log_ids=failed, matching_log_count=len(matches), semantics='Literal >=90 source baseline; zero is a distinct source failure, no new NSG-flow-log creation recommendation or retention-enforcement claim')


def _flow(target, days=90, enabled=True):
    return {'id': FLOW_ID, 'properties': {'targetResourceId': target, 'enabled': enabled, 'retentionPolicy': {'days': days}}}
CASES[SOURCE_QUERIES['network_sg_flowlog_retention_period_greater_than_90']] = {'pass': {'id': NSG_ID}, 'fail': {'id': NSG_ID}, 'pass_index': _fixture('flow_log', [_flow(NSG_ID, 90)]), 'fail_index': _fixture('flow_log', [_flow(NSG_ID, 89)])}


@port('network_virtual_network_watcher_flow_log_retention_90_days', 'flow_log', 'VNet flow-log declaration is enabled with at least 90 days or unlimited retention')
def vnet_retention(item, index):
    target = get(item, 'properties.targetResourceId', str)
    if '/Microsoft.Network/virtualNetworks/' not in target:
        return 'NOT_APPLICABLE', {'reason': 'Pinned source target selector excludes non-VNet flow logs'}
    enabled = get(item, 'properties.enabled', bool)
    days = get(item, 'properties.retentionPolicy.days', int)
    if days < 0:
        raise Unavailable('Malformed negative flow-log retention')
    return result(not enabled or not (days == 0 or days >= 90), enabled=enabled, days=days, semantics='Literal VNet source allows0 for indefinite retention; storage lifecycle/delivery are separate')
CASES[SOURCE_QUERIES['network_virtual_network_watcher_flow_log_retention_90_days']] = {'pass': _flow(VNET_ID, 0), 'fail': _flow(VNET_ID, 89)}
