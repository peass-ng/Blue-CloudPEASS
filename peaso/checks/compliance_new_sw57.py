"""Signed Kubernetes defensive checks for swarm slice 57.

Only complete, cluster-bound snapshot facts can establish PASS or FAIL.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from dataclasses import replace
from datetime import datetime

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get

SPECS = {'k8s_networkpolicy_cluster_has_network_policies_that_1fd253608e': {'resource_kind': 'networkpolicy',
                                                                    'category': 'network',
                                                                    'severity': 'medium',
                                                                    'title': 'Core',
                                                                    'remediation_hint': 'Narrow '
                                                                                        'spec.ingress[].from[].ipBlock.cidr '
                                                                                        'to trusted ranges '
                                                                                        'or limit '
                                                                                        'spec.ingress[].ports '
                                                                                        'to the approved '
                                                                                        'protocol/port '
                                                                                        'pairs.',
                                                                    'sha': 'a1e4fc801622d32658ead5ed6097263ed610377465469826b8aa54a9e4d16ef4'},
 'k8s_networkpolicy_cluster_has_network_policies_that_24d2fc90b0': {'resource_kind': 'networkpolicy',
                                                                    'category': 'network',
                                                                    'severity': 'medium',
                                                                    'title': 'Checks if a Kubernetes Cluster '
                                                                             'has network policies that '
                                                                             'restrict public access',
                                                                    'remediation_hint': 'Remove non-22 '
                                                                                        'entries from '
                                                                                        'spec.ingress[].ports '
                                                                                        'and set protocol: '
                                                                                        'TCP, port: 22 in '
                                                                                        'the NetworkPolicy '
                                                                                        'manifest.',
                                                                    'sha': 'f14ac3e21c2f054c5ffbe104e1aa81188fc062af4085a877df75972e18299e37'},
 'k8s_networkpolicy_has_ingress_or_egress_rules': {'resource_kind': 'networkpolicy',
                                                   'category': 'network',
                                                   'severity': 'medium',
                                                   'title': 'NetworkPolicy isolation declaration agrees with '
                                                            'approved intent',
                                                   'remediation_hint': 'Review the selected Pods, '
                                                                       'policyTypes, owner-approved allow or '
                                                                       'deny intent, and CNI enforcement '
                                                                       'before changing NetworkPolicy rules; '
                                                                       'retain intentional default-deny '
                                                                       'policies.',
                                                   'sha': '52d8472088c73ca7c64893c85b2bd371da4ec3a9d0e7fa662db52972b8809044'},
 'k8s_networkpolicy_world_ingress_authorized_ports': {'resource_kind': 'networkpolicy',
                                                      'category': 'network',
                                                      'severity': 'medium',
                                                      'title': 'Core',
                                                      'remediation_hint': 'Set ingress.ports to the approved '
                                                                          'protocol/port pairs for any rule '
                                                                          'with 0.0.0.0/0 or ::/0 in '
                                                                          'ingress.from.',
                                                      'sha': 'd34626295c73711c17c982ee63c46e927173a0523eff20b24c56445313ff8b5a'},
 'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4': {'resource_kind': 'cluster',
                                                                        'category': 'hardening',
                                                                        'severity': 'medium',
                                                                        'title': 'Clock Synchronisation',
                                                                        'remediation_hint': 'Configure '
                                                                                            'chronyd or the '
                                                                                            'node time '
                                                                                            'synchronization '
                                                                                            'service against '
                                                                                            'approved NTP '
                                                                                            'sources and '
                                                                                            'verify each '
                                                                                            'node clock is '
                                                                                            'within the '
                                                                                            'approved '
                                                                                            'tolerance.',
                                                                        'sha': 'f5867aec50ad5c0bf5936aef9ee480dee26039b183ae0bd10989df7936b2fdc0'},
 'k8s_privileged_utility_access': {'resource_kind': 'cluster',
                                   'category': 'least_privilege',
                                   'severity': 'high',
                                   'title': 'Restrict Kubernetes privileged utilities',
                                   'remediation_hint': 'Remove unapproved RBAC grants for pods/exec create '
                                                       'and pods/ephemeralcontainers update, and restrict '
                                                       'privileged utility Pods to authorized namespaces.',
                                   'sha': 'c054b202fe5061aaa34f915bc869ce7c2918ac3fc008d361a604f1b80a567265'},
 'k8s_cluster_appropriate_set_procedures_information_labelling_should_e24bda19': {'resource_kind': 'namespace',
                                                                                  'category': 'hardening',
                                                                                  'severity': 'medium',
                                                                                  'title': 'Classification '
                                                                                           'Of Information',
                                                                                  'remediation_hint': 'Set '
                                                                                                      'metadata.labels[classification_label_key] '
                                                                                                      'to an '
                                                                                                      'approved '
                                                                                                      'classification '
                                                                                                      'value '
                                                                                                      'in '
                                                                                                      'each '
                                                                                                      'Namespace, '
                                                                                                      'Secret, '
                                                                                                      'Pod '
                                                                                                      'and '
                                                                                                      'Deployment '
                                                                                                      'manifest '
                                                                                                      'or '
                                                                                                      'template.',
                                                                                  'sha': '5d91d17cc2bffa0f4ef62fcbb2b736d77b2b1f606f1adc0d6c274ca7659aae20'},
 'k8s_environment_separation': {'resource_kind': 'namespace',
                                'category': 'network',
                                'severity': 'medium',
                                'title': 'Check declared environment segregation',
                                'remediation_hint': 'Label each namespace with the approved environment, '
                                                    'remove cross-environment RoleBindings, and replace '
                                                    'cross-environment NetworkPolicy peers with approved '
                                                    'namespaceSelectors.',
                                'sha': 'a51276c77a8c5288c658a5ec27924674b10de33a59cd02e352f7371b160280e1'},
 'k8s.cis.file_pki_owner': {'resource_kind': 'file_metadata',
                            'category': 'hardening',
                            'severity': 'medium',
                            'title': 'Ensure that the Kubernetes PKI directory and file ownership is set to '
                                     'root:root',
                            'remediation_hint': 'On each control-plane node, run `chown -R root:root '
                                                '/etc/kubernetes/pki` after verifying PKI ownership '
                                                'requirements.',
                            'sha': 'a69344c8ffa20787da6391fb359154874af550438f0a4af9c62af06e098a96bc'},
 'k8s.cis.file_var_lib_etcd_owner': {'resource_kind': 'file_metadata',
                                     'category': 'hardening',
                                     'severity': 'medium',
                                     'title': 'Ensure that the etcd data directory ownership is set to '
                                              'etcd:etcd',
                                     'remediation_hint': 'On each etcd node, resolve the local etcd UID and '
                                                         'GID and run `chown etcd:etcd /var/lib/etcd`; '
                                                         'verify the service account configured for that '
                                                         'node.',
                                     'sha': '842f7718dc226a855b09f288f950c8fca39e6b87c2ce527e8c8fa7d049e03d30'},
 'k8s.cis.the_ipaddressdeny_is_set_to_any': {'resource_kind': 'component_configuration',
                                             'category': 'network',
                                             'severity': 'medium',
                                             'title': 'Ensure that the --IPAddressDeny is set to any',
                                             'remediation_hint': 'Set the Windows node IPAddressDeny policy '
                                                                 'value to Any using the node management '
                                                                 'policy, then confirm it on each Windows '
                                                                 'node.',
                                             'sha': '1222f065246cd126adf46368717e85fcd62d2e323e3c42bcd20b6066f92b7f7b'},
 'k8s.cis.avoid_use_of_system_masters_group': {'resource_kind': 'clusterrolebinding',
                                               'category': 'iam',
                                               'severity': 'high',
                                               'title': 'Avoid use of system:masters group',
                                               'remediation_hint': 'Remove system:masters subjects from '
                                                                   'RoleBindings and ClusterRoleBindings; '
                                                                   'grant a narrowly scoped Role or '
                                                                   'ClusterRole to named groups instead.',
                                               'sha': '889fa81459bc8e70895673a3e4f0a61fdc4ae8496de8faf1fb16ce642ee50c72'},
 'k8s.cis.psp_binding_enforced': {'resource_kind': 'clusterrolebinding',
                                  'category': 'hardening',
                                  'severity': 'medium',
                                  'title': 'Legacy PodSecurityPolicy is bound and usable',
                                  'remediation_hint': 'On Kubernetes versions serving PSP, bind each '
                                                      'workload ServiceAccount to an approved restrictive '
                                                      'PodSecurityPolicy using an RBAC Role with `use` on '
                                                      'that policy; migrate to Pod Security Admission before '
                                                      'upgrading.',
                                  'sha': 'ae51b4bfae6f423bbbbc7333b75bee293f5eba2eed515a9a8d48151e20eb586e'},
 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0': {'resource_kind': 'role,clusterrole',
                                                                                       'category': 'least_privilege',
                                                                                       'severity': 'high',
                                                                                       'title': 'Checks if '
                                                                                                'your '
                                                                                                'Kubernetes '
                                                                                                'PersistentVolumeClaims '
                                                                                                '(PVC) '
                                                                                                'permissions '
                                                                                                'do not '
                                                                                                'allow other '
                                                                                                'inter-namespace '
                                                                                                'access '
                                                                                                'except for '
                                                                                                'the control '
                                                                                                'namespace '
                                                                                                'policy that '
                                                                                                'you pr',
                                                                                       'remediation_hint': 'Remove '
                                                                                                           'the '
                                                                                                           'offending '
                                                                                                           'RoleBinding '
                                                                                                           'or '
                                                                                                           'ClusterRoleBinding, '
                                                                                                           'or '
                                                                                                           'replace '
                                                                                                           'it '
                                                                                                           'with '
                                                                                                           'a '
                                                                                                           'namespace-scoped '
                                                                                                           'Role '
                                                                                                           'limited '
                                                                                                           'to '
                                                                                                           'approved '
                                                                                                           'ServiceAccounts '
                                                                                                           'and '
                                                                                                           'PVC '
                                                                                                           'verbs.',
                                                                                       'sha': '37a23a1e881ce9809dfe8083fd165ff12fa76860e5090353a9acf4b19c3900a3'}}


def _context(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'k8s':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    cluster = get(context, 'metadata.cluster_id', str)
    if not scope or not cluster:
        raise Unavailable('scope or cluster identity missing')
    return context, scope, cluster


def _inventory(index, kind):
    _, scope, cluster = _context(index)
    pages = get(get(index, 'collections', dict), kind, list)
    if not pages or any(not isinstance(p, dict) or p.get('type') != kind or p.get('scope') != scope or p.get('status') not in ('collected', 'empty') for p in pages):
        raise Unavailable('incomplete or foreign-scope ' + kind + ' inventory')
    wrappers = get(index, kind, list)
    if any(not isinstance(w, dict) or w.get('type') != kind or w.get('scope') != scope or w.get('provider', 'k8s') != 'k8s' for w in wrappers):
        raise Unavailable('foreign-scope ' + kind + ' resource')
    rows = complete_items(index, kind)
    if len(rows) != len(wrappers) or sum(len(get(p, 'items', list)) for p in pages) != len(rows):
        raise Unavailable('inventory content mismatch')
    page_rows = [v for p in pages for v in get(p, 'items', list)]
    if any(not isinstance(v, dict) for v in page_rows):
        raise Unavailable('malformed inventory item')
    try:
        if Counter(json.dumps(v, sort_keys=True) for v in rows) != Counter(json.dumps(v, sort_keys=True) for v in page_rows):
            raise Unavailable('inventory content mismatch')
    except (TypeError, ValueError) as exc:
        raise Unavailable('inventory content malformed') from exc
    identities = set()
    for row in rows:
        provenance = row.get('provenance', {})
        if not isinstance(provenance, dict) or provenance.get('cluster_id') != cluster:
            raise Unavailable('foreign cluster or missing provenance')
        if kind in ('networkpolicy', 'role', 'rolebinding', 'pod', 'deployment', 'secret_metadata'):
            ns = get(row, 'metadata.namespace', str)
            if not ns or scope != '*' and ns != scope:
                raise Unavailable('foreign namespace in ' + kind)
        else:
            ns = None
        if kind in ('networkpolicy', 'role', 'rolebinding', 'pod', 'deployment', 'secret_metadata', 'namespace', 'node', 'clusterrole', 'clusterrolebinding', 'podsecuritypolicy'):
            name = get(row, 'metadata.name', str)
            identity = (ns, name)
            if not name or identity in identities or kind == 'namespace' and scope != '*' and name != scope:
                raise Unavailable('duplicate, malformed or foreign-scope resource identity')
            identities.add(identity)
    return rows


def _member(item, index, kind):
    rows = _inventory(index, kind)
    if item not in rows:
        raise Unavailable('resource not in complete inventory')
    return rows


def _opt(obj, key, default, source):
    if key in obj or key in obj.get('_coverage', {}):
        return get(obj, key)
    if get(source, 'provenance.evidence', str) == 'read-only list':
        return default
    raise Unavailable('omitted field in partial representation: ' + key)


def _policy(index, key, expected):
    context, _, cluster = _context(index)
    p = get(context, 'metadata.compliance_policy', dict)
    if get(p, 'status', str) != 'collected' or get(p, 'cluster_id', str) != cluster:
        raise Unavailable('owner policy absent or foreign cluster')
    if 'observed_at' in p or 'max_age_seconds' in p:
        at = get(p, 'observed_at', str)
        age = get(p, 'max_age_seconds', int)
        captured = get(context, 'created_at', str)
        try:
            a, b = (datetime.fromisoformat(s.replace('Z', '+00:00')) for s in (at, captured))
            if a.utcoffset() is None or b.utcoffset() is None or age <= 0 or not 0 <= (b-a).total_seconds() <= age:
                raise ValueError('stale policy')
        except ValueError as exc:
            raise Unavailable('owner policy freshness unresolved') from exc
    return get(p, key, expected)


def _strings(index, key):
    values = _policy(index, key, list)
    if any(not isinstance(v, str) or not v for v in values) or len(set(values)) != len(values):
        raise Unavailable('malformed owner list: ' + key)
    return set(values)



def _enforcement(index, *, union=False):
    _, scope, cluster = _context(index)
    evidence = get(index, 'context.metadata.network_policy_enforcement', dict)
    if evidence.get('status') != 'verified' or evidence.get('cluster_id') != cluster or evidence.get('scope') != scope:
        raise Unavailable('CNI enforcement unavailable or foreign scope')
    if union and evidence.get('policy_union_complete') is not True:
        raise Unavailable('NetworkPolicy union coverage unresolved')
    return evidence

def _ports(index, key):
    values = _policy(index, key, list)
    if not values:
        raise Unavailable('empty approved ports')
    out = set()
    for v in values:
        proto, port = get(v, 'protocol', str), get(v, 'port')
        if proto not in ('TCP', 'UDP', 'SCTP') or isinstance(port, bool) or not (type(port) is int and 1 <= port <= 65535 or isinstance(port, str) and port):
            raise Unavailable('malformed approved port')
        if (proto, port) in out:
            raise Unavailable('duplicate approved port')
        out.add((proto, port))
    return out



def _selector(selector, source):
    if not isinstance(selector, dict):
        raise Unavailable('Kubernetes selector malformed')
    labels = _opt(selector, 'matchLabels', {}, source)
    expressions = _opt(selector, 'matchExpressions', [], source)
    if not isinstance(labels, dict) or any(not isinstance(k, str) or not k or not isinstance(v, str) for k, v in labels.items()) or not isinstance(expressions, list):
        raise Unavailable('Kubernetes selector malformed')
    for expression in expressions:
        key = get(expression, 'key', str)
        operator = get(expression, 'operator', str)
        values = _opt(expression, 'values', [], source)
        if not key or operator not in ('In', 'NotIn', 'Exists', 'DoesNotExist') or not isinstance(values, list) or any(not isinstance(v, str) for v in values) or (operator in ('In', 'NotIn')) != bool(values):
            raise Unavailable('Kubernetes selector expression malformed')
    return labels, expressions

def _rules(item):
    spec = get(item, 'spec', dict)
    _selector(get(spec, 'podSelector', dict), item)
    implicit_egress = _opt(spec, 'egress', [], item)
    types = _opt(spec, 'policyTypes', ['Ingress', 'Egress'] if implicit_egress else ['Ingress'], item)
    if not isinstance(types, list) or not types or any(t not in ('Ingress', 'Egress') for t in types) or len(set(types)) != len(types):
        raise Unavailable('policyTypes malformed')
    ingress = _opt(spec, 'ingress', [], item)
    egress = _opt(spec, 'egress', [], item)
    if not isinstance(ingress, list) or not isinstance(egress, list) or any(not isinstance(r, dict) for r in ingress+egress):
        raise Unavailable('NetworkPolicy rules malformed')
    return types, ingress, egress


def _public(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise Unavailable('invalid ipBlock CIDR') from exc
    if network.prefixlen == 0:
        return True
    if network.is_global:
        return True
    if network.is_private or network.is_loopback or network.is_link_local:
        return False
    raise Unavailable('public range cannot be established')


def _peer_public(rule, source):
    peers = _opt(rule, 'from', None, source)
    if peers is None or peers == []:
        return True
    if not isinstance(peers, list):
        raise Unavailable('ingress peers malformed')
    seen = False
    for peer in peers:
        if not isinstance(peer, dict):
            raise Unavailable('ingress peer malformed')
        if 'ipBlock' in peer:
            block = get(peer, 'ipBlock', dict)
            cidr = get(block, 'cidr', str)
            exceptions = _opt(block, 'except', [], source)
            if not isinstance(exceptions, list) or any(not isinstance(x, str) for x in exceptions):
                raise Unavailable('ipBlock exceptions malformed')
            try:
                parent = ipaddress.ip_network(cidr, strict=True)
                if any(not ipaddress.ip_network(x, strict=True).subnet_of(parent) for x in exceptions):
                    raise ValueError('exception outside parent')
            except ValueError as exc:
                raise Unavailable('ipBlock exceptions malformed') from exc
            # Exceptions can remove the public portion; without a proof, do not assert exposure.
            if exceptions and _public(cidr):
                raise Unavailable('ipBlock public range after exceptions unresolved')
            seen |= _public(cidr)
        elif 'namespaceSelector' in peer or 'podSelector' in peer:
            if 'namespaceSelector' in peer:
                _selector(get(peer, 'namespaceSelector', dict), source)
            if 'podSelector' in peer:
                _selector(get(peer, 'podSelector', dict), source)
        else:
            raise Unavailable('unrecognized ingress peer')
    return seen



def _explicit_public(rule, source):
    peers = _opt(rule, 'from', [], source)
    if not isinstance(peers, list):
        raise Unavailable('ingress peers malformed')
    found = False
    for peer in peers:
        if not isinstance(peer, dict):
            raise Unavailable('ingress peer malformed')
        if 'ipBlock' in peer:
            block = get(peer, 'ipBlock', dict)
            cidr = get(block, 'cidr', str)
            exceptions = _opt(block, 'except', [], source)
            if not isinstance(exceptions, list) or any(not isinstance(x, str) for x in exceptions):
                raise Unavailable('ipBlock exceptions malformed')
            try:
                parent = ipaddress.ip_network(cidr, strict=True)
                if any(not ipaddress.ip_network(x, strict=True).subnet_of(parent) for x in exceptions):
                    raise ValueError('exception outside parent')
            except ValueError as exc:
                raise Unavailable('ipBlock exceptions malformed') from exc
            if exceptions and _public(cidr):
                raise Unavailable('ipBlock public range after exceptions unresolved')
            found |= _public(cidr)
        elif 'namespaceSelector' in peer or 'podSelector' in peer:
            if 'namespaceSelector' in peer:
                _selector(get(peer, 'namespaceSelector', dict), source)
            if 'podSelector' in peer:
                _selector(get(peer, 'podSelector', dict), source)
        else:
            raise Unavailable('unrecognized ingress peer')
    return found

def _port_pairs(rule, source):
    ports = _opt(rule, 'ports', None, source)
    if ports is None or ports == []:
        return None
    if not isinstance(ports, list):
        raise Unavailable('ingress ports malformed')
    pairs = set()
    for p in ports:
        if not isinstance(p, dict):
            raise Unavailable('ingress port malformed')
        proto = _opt(p, 'protocol', 'TCP', source)
        port = get(p, 'port')
        if proto not in ('TCP', 'UDP', 'SCTP') or isinstance(port, bool) or not (type(port) is int and 1 <= port <= 65535 or isinstance(port, str) and port):
            raise Unavailable('ingress protocol or port malformed')
        if 'endPort' in p:
            end = get(p, 'endPort', int)
            if type(port) is not int or end < port or end > 65535:
                raise Unavailable('ingress port range malformed')
            if end-port > 4096:
                raise Unavailable('ingress port range too broad to enumerate')
            pairs.update((proto, x) for x in range(port, end+1))
        else:
            pairs.add((proto, port))
    return pairs


def _network(item, index, check_id):
    _member(item, index, 'networkpolicy')
    types, ingress, egress = _rules(item)
    if check_id.endswith('1fd253608e') or check_id.endswith('world_ingress_authorized_ports'):
        approved = _ports(index, 'allowed_public_ports' if check_id.endswith('1fd253608e') else 'allowed_ports')
        bad = []
        for n, rule in enumerate(ingress):
            if (_explicit_public(rule, item) if check_id.endswith('1fd253608e') else _peer_public(rule, item)):
                ports = _port_pairs(rule, item)
                if ports is None or not ports <= approved:
                    bad.append(n)
        return result(bool(bad), offending_ingress_rules=bad)
    if check_id.endswith('24d2fc90b0'):
        _enforcement(index, union=True)
        rows = _inventory(index, 'networkpolicy')
        if not rows:
            return unknown('no applicable policy exists')
        bad = []
        applicable = 0
        for policy in rows:
            ptypes, prules, _ = _rules(policy)
            if 'Ingress' not in ptypes:
                continue
            applicable += 1
            for n, rule in enumerate(prules):
                if _peer_public(rule, policy):
                    ports = _port_pairs(rule, policy)
                    if ports is None or any(pair != ('TCP', 22) for pair in ports):
                        bad.append((get(policy, 'metadata.name', str), n))
        if not applicable:
            return unknown('no applicable ingress policy exists')
        return result(bool(bad), offending_rules=bad)
    approved = _policy(index, 'network_policy_intent', dict)
    _enforcement(index)
    key = get(item, 'metadata.namespace', str) + '/' + get(item, 'metadata.name', str)
    expected = approved.get(key)
    if not isinstance(expected, dict):
        raise Unavailable('owner NetworkPolicy intent missing for policy')
    expected_types = get(expected, 'policyTypes', list)
    expected_ingress = get(expected, 'ingress', list)
    expected_egress = get(expected, 'egress', list)
    if any(t not in ('Ingress', 'Egress') for t in expected_types) or any(not isinstance(x, dict) for x in expected_ingress+expected_egress):
        raise Unavailable('owner NetworkPolicy intent malformed')
    if set(types) != set(expected_types) or bool(ingress) != bool(expected_ingress) or bool(egress) != bool(expected_egress):
        return result(True, policy=key, semantics='definite isolation or allow-rule presence deviation')
    if ingress != expected_ingress or egress != expected_egress:
        return unknown('allow-rule semantic equivalence unresolved', policy=key)
    return result(False, policy=key, semantics='exact approved declaration and attested CNI enforcement')

def _bindings(index):
    bindings = []
    for kind in ('rolebinding', 'clusterrolebinding'):
        for row in _inventory(index, kind):
            namespace = get(row, 'metadata.namespace', str) if kind == 'rolebinding' else '*'
            ref = get(row, 'roleRef', dict)
            refkind, name = get(ref, 'kind', str), get(ref, 'name', str)
            if refkind not in ('Role', 'ClusterRole') or not name or kind == 'clusterrolebinding' and refkind != 'ClusterRole':
                raise Unavailable('binding roleRef malformed')
            subjects = _opt(row, 'subjects', [], row)
            if not isinstance(subjects, list):
                raise Unavailable('binding subjects malformed')
            normalized = []
            for s in subjects:
                sk, sn = get(s, 'kind', str), get(s, 'name', str)
                if sk not in ('ServiceAccount', 'User', 'Group') or not sn:
                    raise Unavailable('binding subject malformed')
                sns = get(s, 'namespace', str) if sk == 'ServiceAccount' and 'namespace' in s else namespace
                if sk == 'ServiceAccount' and (not sns or sns == '*'):
                    raise Unavailable('ServiceAccount namespace unresolved')
                normalized.append((sk, sn, sns))
            bindings.append((kind, namespace, refkind, name, normalized))
    return bindings


def _roles(index):
    out = {}
    for kind in ('role', 'clusterrole'):
        for row in _inventory(index, kind):
            ns = get(row, 'metadata.namespace', str) if kind == 'role' else '*'
            name = get(row, 'metadata.name', str)
            key = (kind, ns, name)
            if not name or key in out:
                raise Unavailable('duplicate or malformed RBAC role identity')
            rules = _opt(row, 'rules', [], row)
            if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
                raise Unavailable('RBAC rules malformed')
            out[key] = rules
    return out


def _effective(index):
    roles = _roles(index)
    for binding_kind, ns, refkind, name, subjects in _bindings(index):
        key = ('role' if refkind == 'Role' else 'clusterrole', ns if refkind == 'Role' else '*', name)
        if key not in roles:
            raise Unavailable('binding roleRef unresolved')
        yield binding_kind, ns, subjects, roles[key]


def _rule_grants(rule, resource, verb, group=''):
    groups = get(rule, 'apiGroups', list)
    resources = get(rule, 'resources', list)
    verbs = get(rule, 'verbs', list)
    if any(not isinstance(v, str) for v in groups) or any(not isinstance(v, str) or not v for seq in (resources, verbs) for v in seq):
        raise Unavailable('RBAC rule malformed')
    return (group in groups or '*' in groups) and (resource in resources or '*' in resources) and (verb in verbs or '*' in verbs)


def _privileged(index):
    allowed_subjects = _strings(index, 'authorized_subjects')
    allowed_namespaces = _strings(index, 'authorized_utility_namespaces')
    utility_pods = _strings(index, 'privileged_utility_pods')
    if any(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', ns) is None for ns in allowed_namespaces) or any('/' not in value or not all(value.split('/', 1)) for value in utility_pods) or any(not re.fullmatch(r'(?:ServiceAccount:[^/]+/[^/]+|User:.+|Group:.+)', value) for value in allowed_subjects):
        raise Unavailable('utility authorization policy malformed')
    bad = []
    for _, ns, subjects, rules in _effective(index):
        if any(_rule_grants(rule, 'pods/exec', 'create') or _rule_grants(rule, 'pods/ephemeralcontainers', 'update') for rule in rules):
            for kind, name, sns in subjects:
                identity = f'{kind}:{sns}/{name}' if kind == 'ServiceAccount' else f'{kind}:{name}'
                if identity not in allowed_subjects:
                    bad.append(identity)
    for pod in _inventory(index, 'pod'):
        ns = get(pod, 'metadata.namespace', str)
        containers = list(get(pod, 'spec.containers', list))
        if not containers or any(not isinstance(c, dict) for c in containers):
            raise Unavailable('Pod containers malformed')
        privileged = False
        for field in ('initContainers', 'ephemeralContainers'):
            extra = _opt(get(pod, 'spec', dict), field, [], pod)
            if not isinstance(extra, list) or any(not isinstance(c, dict) for c in extra):
                raise Unavailable('Pod auxiliary containers malformed')
            containers += extra
        for c in containers:
            sc = _opt(c, 'securityContext', {}, pod)
            if not isinstance(sc, dict):
                raise Unavailable('container securityContext malformed')
            value = _opt(sc, 'privileged', False, pod)
            if type(value) is not bool:
                raise Unavailable('container privileged malformed')
            privileged |= value
        if privileged and ns + '/' + get(pod, 'metadata.name', str) in utility_pods and ns not in allowed_namespaces:
            bad.append('Pod:' + ns + '/' + get(pod, 'metadata.name', str))
    return result(bool(bad), unauthorized=sorted(set(bad)))


def _labels(item, source):
    meta = get(item, 'metadata', dict)
    labels = _opt(meta, 'labels', {}, source)
    if not isinstance(labels, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items()):
        raise Unavailable('metadata labels malformed')
    return labels


def _classification(item, index):
    _member(item, index, 'namespace')
    key = _policy(index, 'classification_label_key', str)
    approved = _strings(index, 'approved_values')
    if not key or not approved or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*(?:/[A-Za-z0-9][A-Za-z0-9_.-]*)?', key) is None:
        raise Unavailable('classification policy malformed')
    bad = []
    for kind in ('namespace', 'secret_metadata', 'pod', 'deployment'):
        for row in _inventory(index, kind):
            name = get(row, 'metadata.name', str)
            if _labels(row, row).get(key) not in approved:
                bad.append(kind + ':' + name)
    return result(bool(bad), unlabeled_or_unapproved=bad)


def _environment(item, index):
    _member(item, index, 'namespace')
    matrix = _policy(index, 'environment_matrix', dict)
    key = get(matrix, 'environment_key', str)
    assignments = get(matrix, 'namespaces', dict)
    allowed = get(matrix, 'allowed_cross_environment', list)
    subject_environments = get(matrix, 'subject_environments', dict)
    if not key or any(not isinstance(k, str) or not isinstance(v, str) for k, v in assignments.items()) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in subject_environments.items()) or any(not isinstance(x, list) or len(x) != 2 or any(not isinstance(y, str) for y in x) for x in allowed):
        raise Unavailable('environment matrix malformed')
    _enforcement(index)
    namespaces = _inventory(index, 'namespace')
    actual = {}
    bad = []
    for ns in namespaces:
        name = get(ns, 'metadata.name', str)
        if name not in assignments or name in actual:
            raise Unavailable('namespace environment assignment missing or duplicate')
        actual[name] = _labels(ns, ns)
        if actual[name].get(key) != assignments[name]:
            bad.append('label:' + name)
    environments = set(assignments.values())
    if not environments or any(value not in environments for value in subject_environments.values()) or any(a not in environments or b not in environments for a, b in allowed):
        raise Unavailable('environment matrix references unknown environment')
    if _context(index)[1] == '*' and set(assignments) != set(actual):
        raise Unavailable('environment matrix namespace coverage incomplete')
    permits = {tuple(pair) for pair in allowed}
    for _, target, subjects, _ in _effective(index):
        for kind, name, origin in subjects:
            if kind == 'ServiceAccount':
                if origin not in assignments:
                    raise Unavailable('ServiceAccount environment unresolved')
                source_env = assignments[origin]
            else:
                identity = kind + ':' + name
                if identity not in subject_environments:
                    raise Unavailable('User or Group environment unresolved')
                source_env = subject_environments[identity]
            targets = set(assignments.values()) if target == '*' else {assignments[target]} if target in assignments else None
            if targets is None:
                raise Unavailable('binding target environment unresolved')
            for target_env in targets:
                if source_env != target_env and (source_env, target_env) not in permits:
                    bad.append('binding:' + kind + ':' + name + '->' + target_env)
    for policy in _inventory(index, 'networkpolicy'):
        ns = get(policy, 'metadata.namespace', str)
        _, ingress, egress = _rules(policy)
        for rules, direction in ((ingress, 'from'), (egress, 'to')):
            for rule in rules:
                peers = _opt(rule, direction, [], policy)
                if not isinstance(peers, list):
                    raise Unavailable('NetworkPolicy peers malformed')
                for peer in peers:
                    if not isinstance(peer, dict):
                        raise Unavailable('NetworkPolicy peer malformed')
                    if 'namespaceSelector' in peer:
                        selector = get(peer, 'namespaceSelector', dict)
                        labels = _opt(selector, 'matchLabels', {}, policy)
                        expressions = _opt(selector, 'matchExpressions', [], policy)
                        if expressions or not isinstance(labels, dict) or key not in labels:
                            raise Unavailable('namespaceSelector environment unresolved')
                        selected = labels[key]
                        if selected not in set(assignments.values()):
                            raise Unavailable('unknown selected environment')
                        source_env, target_env = ((selected, assignments[ns]) if direction == 'from'
                                                  else (assignments[ns], selected))
                        if source_env != target_env and (source_env, target_env) not in permits:
                            bad.append('networkpolicy:' + source_env + '->' + target_env)
    return result(bool(bad), deviations=bad)


def _file(item, index, check_id):
    _member(item, index, 'file_metadata')
    coverage = get(index, 'context.metadata.file_metadata_coverage', dict)
    _, _, cluster = _context(index)
    if coverage.get('status') != 'attested_complete' or coverage.get('cluster_id') != cluster:
        return unknown('per-node file coverage incomplete')
    if check_id.endswith('file_pki_owner'):
        recursive = get(index, 'context.metadata.file_metadata_recursive_coverage', dict)
        if recursive.get('status') != 'attested_complete' or recursive.get('cluster_id') != cluster or recursive.get('path') != '/etc/kubernetes/pki':
            return unknown('recursive PKI directory coverage incomplete')
    path = get(item, 'path', str)
    node = get(item, 'node_name', str)
    if not path.startswith('/') or not node:
        raise Unavailable('file identity malformed')
    if check_id.endswith('file_pki_owner'):
        if path != '/etc/kubernetes/pki' and not path.startswith('/etc/kubernetes/pki/'):
            return 'NOT_APPLICABLE', {'reason': 'outside Kubernetes PKI tree'}
        uid, gid = get(item, 'uid', int), get(item, 'gid', int)
        return result(uid != 0 or gid != 0, path=path, node=node, uid=uid, gid=gid)
    if path != '/var/lib/etcd':
        return 'NOT_APPLICABLE', {'reason': 'outside etcd data directory'}
    identities = _policy(index, 'resolved_etcd_accounts', dict)
    account = identities.get(node)
    if not isinstance(account, dict):
        raise Unavailable('node-local etcd account resolution missing')
    expected_uid, expected_gid = get(account, 'uid', int), get(account, 'gid', int)
    if expected_uid < 0 or expected_gid < 0:
        raise Unavailable('resolved etcd account malformed')
    uid, gid = get(item, 'uid', int), get(item, 'gid', int)
    return result(uid != expected_uid or gid != expected_gid, path=path, node=node, uid=uid, gid=gid)


def _files_scope(index, check_id):
    rows = _inventory(index, 'file_metadata')
    coverage = get(index, 'context.metadata.file_metadata_coverage', dict)
    _, _, cluster = _context(index)
    if coverage.get('status') != 'attested_complete' or coverage.get('cluster_id') != cluster:
        return unknown('per-node file coverage incomplete')
    if check_id.endswith('file_pki_owner'):
        recursive = get(index, 'context.metadata.file_metadata_recursive_coverage', dict)
        if recursive.get('status') != 'attested_complete' or recursive.get('cluster_id') != cluster or recursive.get('path') != '/etc/kubernetes/pki' or recursive.get('enumeration_complete') is not True:
            return unknown('recursive PKI directory coverage incomplete')
        expected = get(recursive, 'applicable_nodes', list)
        if any(not isinstance(name, str) or not name for name in expected) or len(set(expected)) != len(expected):
            raise Unavailable('recursive PKI node coverage malformed')
        target = [row for row in rows if get(row, 'path', str) == '/etc/kubernetes/pki' or get(row, 'path', str).startswith('/etc/kubernetes/pki/')]
        observed_roots = {get(row, 'node_name', str) for row in target if get(row, 'path', str) == '/etc/kubernetes/pki'}
        if observed_roots != set(expected) or any(get(row, 'node_name', str) not in expected for row in target):
            return unknown('PKI root or per-node recursive file coverage missing')
    else:
        paths = get(coverage, 'selector_paths', dict)
        if '/var/lib/etcd' not in paths:
            return unknown('etcd selector path coverage missing')
        expected_rows = get(paths, '/var/lib/etcd', list)
        expected = set()
        for row in expected_rows:
            name = get(row, 'node_name', str)
            if not name or name in expected or get(row, 'path', str) != '/var/lib/etcd':
                raise Unavailable('etcd per-node selector coverage malformed')
            expected.add(name)
        target = [row for row in rows if get(row, 'path', str) == '/var/lib/etcd']
        observed = [get(row, 'node_name', str) for row in target]
        if set(observed) != expected or len(observed) != len(set(observed)):
            return unknown('etcd path missing for an applicable node')
    if not target:
        return 'NOT_APPLICABLE', {'reason': 'no applicable file path in attested node coverage'}
    failed = []
    for row in target:
        status, evidence = _file(row, index, check_id)
        if status == 'UNKNOWN':
            return status, evidence
        if status == 'FAIL':
            failed.append({'node': evidence['node'], 'path': evidence['path']})
    return result(bool(failed), offending_files=failed, assessed_files=len(target))

def _version(index):
    rows = _inventory(index, 'api_discovery')
    if len(rows) != 1:
        raise Unavailable('API discovery ambiguous')
    version = get(rows[0], 'serverVersion.gitVersion', str)
    match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.\-]+)?', version)
    if not match:
        raise Unavailable('Kubernetes server version malformed')
    return tuple(map(int, match.groups()))


def _psp(index):
    if _version(index) >= (1, 25, 0):
        return 'NOT_APPLICABLE', {'reason': 'PodSecurityPolicy removed in Kubernetes 1.25+'}
    policies = _inventory(index, 'podsecuritypolicy')
    names = {get(p, 'metadata.name', str) for p in policies}
    if len(names) != len(policies):
        raise Unavailable('PodSecurityPolicy identity duplicate')
    grants = {}
    for _, ns, subjects, rules in _effective(index):
        can_create = any(_rule_grants(rule, 'pods', 'create') for rule in rules)
        can_use = set()
        for rule in rules:
            if _rule_grants(rule, 'podsecuritypolicies', 'use', 'policy'):
                resource_names = get(rule, 'resourceNames', list) if 'resourceNames' in rule or 'resourceNames' in rule.get('_coverage', {}) else []
                if any(not isinstance(n, str) or not n for n in resource_names):
                    raise Unavailable('PSP resourceNames malformed')
                can_use.update(resource_names or names)
        targets = {get(row, 'metadata.name', str) for row in _inventory(index, 'namespace')} if ns == '*' else {ns}
        for kind, name, sns in subjects:
            if kind != 'ServiceAccount':
                continue
            for target in targets:
                entry = grants.setdefault((sns, name, target), {'create': False, 'use': set()})
                entry['create'] |= can_create
                entry['use'].update(can_use & names)
    missing = sorted(f'{ns}/{name}->{target}' for (ns, name, target), grants_for_subject in grants.items()
                     if grants_for_subject['create'] and not grants_for_subject['use'])
    return result(bool(missing), service_accounts_without_psp=missing)


def _masters(index):
    bad = []
    for kind in ('rolebinding', 'clusterrolebinding'):
        for binding in _inventory(index, kind):
            subjects = _opt(binding, 'subjects', [], binding)
            if not isinstance(subjects, list):
                raise Unavailable('binding subjects malformed')
            for subject in subjects:
                if get(subject, 'kind', str) == 'Group' and get(subject, 'name', str) == 'system:masters':
                    bad.append(kind + ':' + get(binding, 'metadata.name', str))
    if bad:
        return result(True, observed_bindings=bad)
    return unknown('certificate and provider identity memberships are not observed')


def _pvc(index):
    controls = _strings(index, 'approved_control_namespaces')
    if any(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', name) is None for name in controls):
        raise Unavailable('approved control namespace malformed')
    bad = []
    for _, target, subjects, rules in _effective(index):
        pvc = any(_rule_grants(rule, 'persistentvolumeclaims', verb) for rule in rules
                  for verb in ('get', 'list', 'watch', 'create', 'update', 'patch', 'delete', 'deletecollection'))
        if not pvc:
            continue
        for kind, name, origin in subjects:
            if kind != 'ServiceAccount':
                continue
            if target == '*':
                namespaces = {get(ns, 'metadata.name', str) for ns in _inventory(index, 'namespace')}
                targets = namespaces - {origin} - controls
            else:
                targets = {target} - {origin} - controls
            for ns in targets:
                bad.append(f'{origin}/{name}->{ns}')
    return result(bool(bad), unauthorized_cross_namespace_pvc_grants=sorted(set(bad)))


def _windows(index):
    nodes = _inventory(index, 'node')
    windows = {}
    for node in nodes:
        name = get(node, 'metadata.name', str)
        os = get(node, 'status.nodeInfo.operatingSystem', str)
        if os not in ('linux', 'windows') or name in windows:
            raise Unavailable('node OS or identity malformed')
        if os == 'windows':
            windows[name] = node
    if not windows:
        return 'NOT_APPLICABLE', {'reason': 'no Windows nodes in complete Node inventory'}
    configs = _inventory(index, 'component_configuration')
    observed = {}
    for config in configs:
        if get(config, 'component', str) != 'kubelet':
            continue
        name = get(config, 'node_name', str)
        if name in observed:
            raise Unavailable('duplicate component configuration')
        if name in windows:
            observed[name] = get(config, 'configuration.IPAddressDeny', str)
    if set(observed) != set(windows):
        raise Unavailable('Windows node configuration unavailable')
    if any(not value for value in observed.values()):
        raise Unavailable('Windows IPAddressDeny malformed')
    return result(any(value != 'Any' for value in observed.values()), observed=observed)


def _clock(index):
    tolerance = _policy(index, 'approved_clock_skew', int)
    if tolerance < 0 or tolerance > 86400:
        raise Unavailable('approved clock skew malformed')
    nodes = _inventory(index, 'node')
    clocks = _inventory(index, 'node_clock')
    from peaso.collectors import k8s_node_clock_evidence as external_clock
    if any(clock.get('source_operation') == external_clock.SOURCE for clock in clocks):
        if any(clock.get('source_operation') != external_clock.SOURCE or
               set(clock) != external_clock.ROW | {'source_operation', 'provenance'} for clock in clocks):
            raise Unavailable('mixed or malformed external clock measurement')
        context, _, cluster = _context(index)
        review = get(context, 'metadata.external_node_clock_review', dict)
        try:
            bad, evidence = external_clock.verdict(
                review, [{key: clock[key] for key in external_clock.ROW} for clock in clocks],
                nodes, _inventory(index, 'namespace'), cluster,
                get(context, 'created_at', str), tolerance)
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            raise Unavailable('external clock measurements incomplete, stale or not reviewed') from exc
        return result(bad, **evidence)
    by_node = {}
    for clock in clocks:
        name = get(clock, 'node_name', str)
        if name in by_node:
            raise Unavailable('duplicate node clock fact')
        by_node[name] = clock
    names = {get(node, 'metadata.name', str) for node in nodes}
    if not names or set(by_node) != names:
        raise Unavailable('node clock coverage missing or foreign')
    bad = []
    for name, clock in by_node.items():
        if get(clock, 'source_operation', str) != 'GET /api/v1/nodes/{name}/proxy/healthz' or get(clock, 'node_response_verified', bool) is not True or get(clock, 'trusted_clock_verified', bool) is not True:
            raise Unavailable('node proxy or trusted clock source unverified')
        header = get(clock, 'date_header', str)
        utc = get(clock, 'trusted_utc_at_response', str)
        try:
            from email.utils import parsedate_to_datetime
            observed = parsedate_to_datetime(header)
            trusted = datetime.fromisoformat(utc.replace('Z', '+00:00'))
            if observed.utcoffset() is None or trusted.utcoffset() is None:
                raise ValueError('timezone missing')
        except ValueError as exc:
            raise Unavailable('node clock timestamps malformed') from exc
        if abs((observed-trusted).total_seconds()) > tolerance:
            bad.append(name)
    return result(bool(bad), out_of_tolerance_nodes=bad, approved_clock_skew_seconds=tolerance)


def _evaluate(check_id, item, index):
    if check_id.startswith('k8s_networkpolicy_'):
        return _network(item, index, check_id)
    if check_id == 'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4':
        return _clock(index)
    if check_id == 'k8s_privileged_utility_access':
        return _privileged(index)
    if check_id == 'k8s_cluster_appropriate_set_procedures_information_labelling_should_e24bda19':
        return _classification(item, index)
    if check_id == 'k8s_environment_separation':
        return _environment(item, index)
    if check_id in ('k8s.cis.file_pki_owner', 'k8s.cis.file_var_lib_etcd_owner'):
        return _files_scope(index, check_id)
    if check_id == 'k8s.cis.the_ipaddressdeny_is_set_to_any':
        return _windows(index)
    if check_id == 'k8s.cis.avoid_use_of_system_masters_group':
        return _masters(index)
    if check_id == 'k8s.cis.psp_binding_enforced':
        return _psp(index)
    if check_id == 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0':
        return _pvc(index)
    raise Unavailable('unknown check id')


DEPENDENCIES = {
    'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4': ('node', 'node_clock'),
    'k8s_privileged_utility_access': ('role', 'clusterrole', 'rolebinding', 'clusterrolebinding', 'pod'),
    'k8s_cluster_appropriate_set_procedures_information_labelling_should_e24bda19': ('namespace', 'secret_metadata', 'pod', 'deployment'),
    'k8s_environment_separation': ('namespace', 'role', 'clusterrole', 'rolebinding', 'clusterrolebinding', 'networkpolicy'),
    'k8s.cis.the_ipaddressdeny_is_set_to_any': ('node',),
    'k8s.cis.avoid_use_of_system_masters_group': ('rolebinding', 'clusterrolebinding'),
    'k8s.cis.psp_binding_enforced': ('api_discovery',),
    'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0': ('role', 'clusterrole', 'rolebinding', 'clusterrolebinding', 'namespace'),
}
SCOPE_IDS = {
    'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4',
    'k8s_privileged_utility_access',
    'k8s.cis.file_pki_owner',
    'k8s.cis.file_var_lib_etcd_owner',
    'k8s.cis.the_ipaddressdeny_is_set_to_any',
    'k8s.cis.avoid_use_of_system_masters_group',
    'k8s.cis.psp_binding_enforced',
    'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0',
}

for _id, _spec in SPECS.items():
    _kind = _spec['resource_kind']
    _deps = DEPENDENCIES.get(_id, (_kind,))
    @register(_id, 'k8s', 'iam_graph' if _spec['category'] == 'iam' else _spec['category'], _kind, _spec['title'], _spec['severity'],
              'CM-6', _spec['remediation_hint'], target='scope' if _id in SCOPE_IDS else 'resource',
              dependencies=_deps)
    def evaluate_sw57(item, index, check_id=_id):
        return _evaluate(check_id, item, index)

    if _spec['category'] == 'iam':
        # The native decorator predates the signed ledger's iam category.
        CHECKS[-1] = replace(CHECKS[-1], category='iam')
