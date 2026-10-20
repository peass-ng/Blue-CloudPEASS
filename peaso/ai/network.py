"""Network-only evidence preparation and publication of attributed AI findings."""
from collections import Counter, defaultdict
import re

from .briefing import compact

# Workload configuration is projected to network facts. Never hand over pod
# environment variables, instance user data, application configuration or IAM.
WORKLOAD_FIELDS = {
    'aws': {'InstanceId', 'VpcId', 'SubnetId', 'SecurityGroups', 'NetworkInterfaces', 'PrivateIpAddress',
            'PublicIpAddress', 'PrivateDnsName', 'PublicDnsName', 'Ipv6Address', 'SourceDestCheck',
            'DBInstanceIdentifier', 'DBSubnetGroup', 'VpcSecurityGroups', 'PubliclyAccessible', 'Endpoint',
            'VpcConfig', 'NetworkConfiguration', 'DNSName', 'Scheme', 'AvailabilityZones', 'IpAddressType',
            'Tags', 'TagList', 'FunctionName', 'Description', 'DBClusterIdentifier', 'DBSubnetGroupDetails', 'State'},
    'gcp': {'id', 'name', 'selfLink', 'labels', 'description', 'networkInterfaces', 'tags', 'serviceAccounts', 'networkConfig',
            'privateClusterConfig', 'ipAllocationPolicy', 'masterAuthorizedNetworksConfig'},
    'azure': {'id', 'name', 'type', 'location', 'tags'},
    'k8s': {'apiVersion', 'kind', 'metadata'},
}
WORKLOAD_TYPES = {'instance', 'vm', 'pod', 'node', 'daemonset', 'lambda_function', 'rds_instance',
                  'rds_cluster', 'eks_cluster', 'gke_cluster', 'container', 'function', 'app_service'}


def without_secrets(value):
    if isinstance(value, dict):
        return {key: without_secrets(item) for key, item in value.items()
                if not re.search(r'password|secret|token|private.?key|pre.?shared|shared.?key|authentication.?key|'
                                 r'customerGatewayConfiguration|user.?data|custom.?data|environment|appSettings', key, re.I)}
    if isinstance(value, (list, tuple)):
        return [without_secrets(item) for item in value]
    return value


def native_network_resource(row):
    from peaso.analysis.network import NETWORK_TYPES
    from peaso.analysis.reachability import REACHABILITY_TYPES
    controls = (NETWORK_TYPES | set().union(*REACHABILITY_TYPES.values())) - WORKLOAD_TYPES
    if row.get('type') in controls:
        return dict(row, data=without_secrets(row.get('data', {})))
    provider, data = row['provider'], row.get('data', {})
    selected = {key: value for key, value in data.items() if key in WORKLOAD_FIELDS.get(provider, set())}
    if provider == 'azure':
        props = data.get('properties') or {}
        selected['properties'] = {key: props[key] for key in ('networkProfile', 'subnet', 'publicNetworkAccess',
            'privateEndpointConnections', 'networkAcls', 'ipConfigurations') if key in props}
    if provider == 'k8s':
        meta = data.get('metadata') or {}
        selected['metadata'] = {key: meta[key] for key in ('name', 'namespace', 'uid', 'labels') if key in meta}
        spec = data.get('spec') or {}
        if row.get('type') == 'daemonset':
            template = spec.get('template') or {}
            selected['template_labels'] = (template.get('metadata') or {}).get('labels', {})
            spec = template.get('spec') or {}
        selected['spec'] = {key: spec[key] for key in ('hostNetwork', 'nodeName', 'podCIDR', 'podCIDRs',
            'dnsPolicy', 'nodeSelector') if key in spec}
        selected['ports'] = [port for container in spec.get('containers', []) for port in container.get('ports', [])]
        status = data.get('status') or {}
        selected['status'] = {key: status[key] for key in ('podIP', 'podIPs', 'hostIP', 'addresses') if key in status}
    return dict(row, data=without_secrets(selected), ai_projection='network fields only; omitted workload settings are unavailable')


def prepare(report, inventory, snapshot):
    from peaso.analysis.reachability import REACHABILITY_TYPES
    from peaso.analysis.network import NETWORK_TYPES
    from peaso.engine import hydrate_finding
    from .pipeline import referenced_strings
    graph = report.get('graphs', {}).get('network') or {}
    types = REACHABILITY_TYPES.get(report['provider'], set()) | NETWORK_TYPES
    references = set(referenced_strings(graph))
    selected = [native_network_resource(row) for row in inventory
                if row.get('type') in types or row['id'] in references]
    if not selected and not graph.get('nodes') and not graph.get('edges'):
        return None
    findings = []
    # A separate issue catalog prevents repeating Exposure without disclosing
    # unrelated native policies, identities or workload configuration. Preserve
    # it through the second projection at the file-writing boundary.
    issue_fields = ('id', 'check_id', 'title', 'resource_id', 'native_resource_id', 'scope', 'status', 'evidence_summary')
    def issue(row):
        return {key: row[key] for key in issue_fields if isinstance(row.get(key), str)}
    exposure = {row['id']: issue(row) for row in report.get('exposure_findings', [])
                if row.get('id') and row.get('status') in ('FAIL', 'MANUAL', 'UNKNOWN', 'DENIED')}
    for raw in report.get('findings', []):
        row = hydrate_finding(raw, report.get('check_frameworks'), report.get('check_meta'),
            report.get('check_meta_encoding'), report.get('remediation_templates'))
        if row.get('category') == 'network':
            findings.append(row)
        elif row.get('category') == 'exposure' and row.get('status') in ('FAIL', 'MANUAL', 'UNKNOWN', 'DENIED'):
            exposure[row['id']] = issue(row)
    network_types = types | {node.get('type') for node in graph.get('nodes', [])}
    coverage = [row for row in report.get('coverage', []) if row.get('level') == 'scope'
                or row.get('type') in network_types]
    scoped = {key: report[key] for key in ('provider', 'snapshot_id', 'created_at', 'scopes') if key in report}
    scoped.update(resources=[{key: value for key, value in row.items() if key != 'data'} for row in selected],
                  findings=findings, graphs={'network': graph}, coverage=coverage,
                  exposure_findings=list(exposure.values()))
    return {'report': scoped, 'inventory': selected}


def build(root, platform, reviews, write_json):
    from .briefing import build as build_context
    # Enforce the handoff at the file-writing boundary as well as scheduling.
    platform = prepare(platform['report'], platform['inventory'], {})
    if platform is None:
        raise ValueError('network_context_unavailable')
    # The lookup database contains native network evidence only. Exposure
    # issue summaries are supplied separately as a deduplication catalog.
    build_context(root, platform, platform['report']['findings'], reviews, write_json)
    write_json(root / 'exposure.json', {'findings': platform['report']['exposure_findings']})
    graph = platform['report']['graphs']['network']
    nodes = graph.get('nodes', [])
    by_id = {row['id']: row for row in nodes}
    groups = defaultdict(list)
    for row in nodes:
        groups[row.get('provider', ''), row.get('scope', ''), row.get('type', 'unknown')].append(row)
    boundaries = {'vpc', 'vnet', 'network', 'subnet', 'subnetwork', 'namespace', 'cluster'}
    edge_groups = defaultdict(list)
    for row in graph.get('edges', []):
        source, target = by_id.get(row.get('source'), {}), by_id.get(row.get('target'), {})
        edge_groups[row.get('type', ''), source.get('type', ''), target.get('type', ''),
                    source.get('scope', ''), target.get('scope', '')].append(row['id'])
    write_json(root / 'topology.json', {
        'version': 1,
        'boundaries': [{key: compact(row[key]) for key in ('id', 'type', 'label', 'scope', 'resource_id', 'native_id', 'unresolved') if key in row}
                       for row in nodes if row.get('type') in boundaries],
        'node_groups': [{'provider': key[0], 'scope': key[1], 'type': key[2], 'count': len(rows),
                         'examples': [row['id'] for row in rows[:3]]} for key, rows in groups.items()],
        'edge_groups': [{'type': key[0], 'source_type': key[1], 'target_type': key[2], 'source_scope': key[3],
                         'target_scope': key[4], 'count': len(ids), 'examples': ids[:3]} for key, ids in edge_groups.items()],
        'resource_counts': dict(Counter(row['type'] for row in platform['inventory'])),
        'semantics': 'Complete boundary list and group catalog; examples are samples. Structural links and rules do not prove reachable flows.'})


def with_findings(report, findings):
    """Return an augmented report without changing deterministic observations."""
    if not findings:
        return report
    known = {row['id'] for row in report.get('findings', [])}
    added = [row for row in findings if row['id'] not in known]
    stats = dict(report.get('stats', {}))
    for key, field, rows in (('by_status', 'status', added),
                             ('by_severity', 'severity', [row for row in added if row['status'] == 'FAIL'])):
        counts = Counter(stats.get(key, {}))
        counts.update(row[field] for row in rows)
        stats[key] = dict(counts)
    stats['finding_count'] = stats.get('finding_count', len(known)) + len(added)
    stats['ai_network_finding_count'] = len(findings)
    return dict(report, findings=report.get('findings', []) + added, stats=stats)
