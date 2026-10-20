"""Finite, conditional reuse of existing read-only PSP/RBAC inventories."""
from copy import deepcopy
import re

CHECK = 'k8s.cis.psp_binding_enforced'
OPTION = '_k8s_legacy_psp_binding_requested'
SUPPORT = frozenset({'namespace', 'role', 'clusterrole', 'rolebinding', 'clusterrolebinding', 'podsecuritypolicy'})
CLUSTER_TYPES = frozenset({'api_discovery', 'clusterrole', 'clusterrolebinding', 'podsecuritypolicy'})


def select(connector, checks):
    connector.setdefault('options', {})[OPTION] = any(c.id == CHECK for c in checks)


def parse_version(value):
    if not isinstance(value, str) or len(value) > 253:
        return None
    match = re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?', value)
    return tuple(map(int, match.groups())) if match else None


def version(discovery):
    try:
        if discovery['type'] != 'api_discovery' or discovery['status'] != 'collected' or len(discovery['items']) != 1:
            return None
        row = discovery['items'][0]
        if row.get('_coverage', {}).get('serverVersion'):
            return None
        value = row['serverVersion']['gitVersion']
        return parse_version(value)
    except (KeyError, TypeError, AttributeError):
        return None


def legacy_support(discovery, active):
    observed = version(discovery)
    if not active or observed is None or observed >= (1, 25, 0):
        return frozenset()
    row = discovery['items'][0]
    if row.get('podSecurityPolicyAdvertised') is not True or row.get('_coverage', {}).get('podSecurityPolicyAdvertised'):
        return frozenset()
    return SUPPORT


def copy_cluster_envelopes(reader, scopes):
    """One real cluster LIST may support each selected evaluation namespace."""
    if len(scopes) < 2:
        return
    for kind in sorted(CLUSTER_TYPES):
        sources = [c for c in reader.collections if c['type'] == kind and c['scope'] == scopes[0]]
        if len(sources) != 1:
            continue
        for scope in scopes[1:]:
            if any(c['type'] == kind and c['scope'] == scope for c in reader.collections):
                continue
            value = deepcopy(sources[0]); value['scope'] = scope
            if kind == 'podsecuritypolicy':
                from .k8s_annotation_indicators_20261020 import MARKER
                for row in value['items']:
                    marker = row.get(MARKER, {})
                    if marker.get('status') == 'bound':
                        marker['source']['scope'] = scope
            capacity = len(value['items']) if reader.budget.max_items is None else max(0, reader.budget.max_items - reader.total)
            if len(value['items']) > capacity:
                value['items'] = value['items'][:capacity]
                value.update(status='partial', error={'code': 'resource_limit', 'kind': 'K8sReadError'})
            reader.total += len(value['items']); reader.collections.append(value)
