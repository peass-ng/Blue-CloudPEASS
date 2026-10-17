"""Conservative signed Kubernetes compliance predicates (sw10).

Only complete, scope-bound inventories may establish absence. Operator policy
is cluster-bound; facts that the current collector omits remain UNKNOWN.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from datetime import datetime
from decimal import Decimal, localcontext

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, optional

# Filled from the signed ten-field entries by the sw10 build step.
SPECS = {'k8s.cis.consider_external_secret_storage': {'resource_kind': 'pod',
                                              'category': 'hardening',
                                              'severity': 'medium',
                                              'title': 'Consider external secret storage',
                                              'remediation_hint': 'Install a CSI Secrets Store driver, '
                                                                  'configure SecretProviderClass for the '
                                                                  'external store, and replace direct Secret '
                                                                  'volumes or environment references in the '
                                                                  'Pod spec where supported.'},
 'k8s.cis.controller_manager_rotate_kubelet_server_certificate_true': {'resource_kind': 'pod',
                                                                       'category': 'hardening',
                                                                       'severity': 'medium',
                                                                       'title': 'kube-controller-manager '
                                                                                'enables '
                                                                                'RotateKubeletServerCertificate',
                                                                       'remediation_hint': 'Set '
                                                                                           '--feature-gates=RotateKubeletServerCertificate=true '
                                                                                           'on '
                                                                                           'kube-controller-manager '
                                                                                           'and roll out its '
                                                                                           'static Pod '
                                                                                           'manifest.'},
 'k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost': {'resource_kind': 'pod',
                                                                  'category': 'network',
                                                                  'severity': 'medium',
                                                                  'title': 'Ensure that the kube-proxy '
                                                                           'metrics service is bound to '
                                                                           'localhost',
                                                                  'remediation_hint': 'Set kube-proxy '
                                                                                      '--metrics-bind-address=127.0.0.1:10249 '
                                                                                      '(or [::1]:10249) in '
                                                                                      'its DaemonSet or '
                                                                                      'component '
                                                                                      'configuration.'},
 'k8s.cis.the_request_timeout_argument_is_set_as_appropriate': {'resource_kind': 'pod',
                                                                'category': 'hardening',
                                                                'severity': 'medium',
                                                                'title': 'Ensure that the --request-timeout '
                                                                         'argument is set as appropriate',
                                                                'remediation_hint': 'Set kube-apiserver '
                                                                                    '--request-timeout to a '
                                                                                    'positive duration no '
                                                                                    'greater than the '
                                                                                    'approved maximum in the '
                                                                                    'static Pod manifest.'},
 'k8s.cis.the_service_account_extend_token_expiration_parameter_is_set_to_false': {'resource_kind': 'pod',
                                                                                   'category': 'hardening',
                                                                                   'severity': 'medium',
                                                                                   'title': 'Ensure that the '
                                                                                            '--service-account-extend-token-expiration '
                                                                                            'parameter is '
                                                                                            'set to false',
                                                                                   'remediation_hint': 'Set '
                                                                                                       'kube-apiserver '
                                                                                                       '--service-account-extend-token-expiration=false '
                                                                                                       'in '
                                                                                                       'the '
                                                                                                       'static '
                                                                                                       'Pod '
                                                                                                       'manifest.'},
 'k8s_pod_pod_deployed_specific_namespace_its_76714f9dfe': {'resource_kind': 'pod',
                                                            'category': 'hardening',
                                                            'severity': 'medium',
                                                            'title': 'Core',
                                                            'remediation_hint': 'Move the workload manifest '
                                                                                'to an approved namespace '
                                                                                'and set nodeSelector or '
                                                                                'nodeAffinity to the '
                                                                                'approved node pool labels.'},
 'k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b': {'resource_kind': 'pod',
                                                               'category': 'hardening',
                                                               'severity': 'medium',
                                                               'title': 'Core',
                                                               'remediation_hint': 'Set metadata.namespace '
                                                                                   'in the Pod or controller '
                                                                                   'manifest to an approved '
                                                                                   'namespace and apply it '
                                                                                   'there.'},
 'k8s_pod_pod_deployed_within_specific_namespace_3790c81f90': {'resource_kind': 'pod',
                                                               'category': 'hardening',
                                                               'severity': 'medium',
                                                               'title': 'Core',
                                                               'remediation_hint': 'Set metadata.namespace '
                                                                                   'to an approved namespace '
                                                                                   'and spec.nodeSelector to '
                                                                                   'the required node pool '
                                                                                   'key/value pairs.'},
 'k8s_pod_pod_deployed_within_specific_namespace_62bb9e62c0': {'resource_kind': 'pod',
                                                               'category': 'hardening',
                                                               'severity': 'medium',
                                                               'title': 'Core',
                                                               'remediation_hint': 'Set metadata.namespace '
                                                                                   'to an approved namespace '
                                                                                   'and add the required '
                                                                                   'metadata.labels to the '
                                                                                   'Pod template.'},
 'k8s_pod_pod_running_within_specific_namespace_0f3d581358': {'resource_kind': 'pod',
                                                              'category': 'hardening',
                                                              'severity': 'medium',
                                                              'title': 'Core',
                                                              'remediation_hint': 'Fix the Pod scheduling or '
                                                                                  'readiness failure, place '
                                                                                  'the workload in an '
                                                                                  'approved namespace, and '
                                                                                  'set the required Pod '
                                                                                  'template labels.'},
 'k8s_pod_serviceaccount_has_rbac_binding': {'resource_kind': 'pod',
                                             'category': 'least_privilege',
                                             'severity': 'medium',
                                             'title': 'Pod ServiceAccount has RBAC binding',
                                             'remediation_hint': 'Create a namespace scoped RoleBinding for '
                                                                 'the Pod’s effective '
                                                                 'spec.serviceAccountName and the minimum '
                                                                 'required Role.'},
 'k8s_networkpolicy_has_ingress_rules': {'resource_kind': 'networkpolicy',
                                         'category': 'network',
                                         'severity': 'medium',
                                         'title': 'NetworkPolicy declares an ingress rule',
                                         'remediation_hint': 'Add a spec.ingress rule with reviewed from '
                                                             'peers and ports to the NetworkPolicy.'},
 'k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c': {'resource_kind': 'networkpolicy',
                                                                              'category': 'network',
                                                                              'severity': 'medium',
                                                                              'title': 'Core',
                                                                              'remediation_hint': 'Set '
                                                                                                  'spec.podSelector.matchLabels '
                                                                                                  'or '
                                                                                                  'matchExpressions '
                                                                                                  'to the '
                                                                                                  'intended '
                                                                                                  'workload '
                                                                                                  'labels.'},
 'k8s_cluster_version_at_least_oldest_supported': {'resource_kind': 'cluster',
                                                   'category': 'hardening',
                                                   'severity': 'medium',
                                                   'title': 'Checks if a Kubernetes cluster is running a '
                                                            'supported version. This rule is NON_COMPLIANT '
                                                            'if the cluster is running an u',
                                                   'remediation_hint': 'Upgrade the control plane and nodes '
                                                                       'to Kubernetes oldestVersionSupported '
                                                                       'or later using the cluster provider '
                                                                       'or kubeadm upgrade plan.'},
 'k8s_cluster_version_supported': {'resource_kind': 'cluster',
                                   'category': 'hardening',
                                   'severity': 'high',
                                   'title': 'Checks if a Kubernetes cluster is running a supported version. '
                                            'This rule is NON_COMPLIANT if the cluster is running an u',
                                   'remediation_hint': 'Upgrade the control plane and nodes to a supported '
                                                       'Kubernetes release above oldestVersionSupported '
                                                       'using the cluster provider or kubeadm upgrade plan.'},
 'k8s.cis.namespace_has_networkpolicy': {'resource_kind': 'namespace',
                                         'category': 'network',
                                         'severity': 'medium',
                                         'title': 'Every namespace has a NetworkPolicy',
                                         'remediation_hint': 'Create a NetworkPolicy in each application '
                                                             'namespace with a podSelector and explicit '
                                                             'ingress and egress rules, beginning with a '
                                                             'default deny policy.'},
 'k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture': {'resource_kind': 'component_configuration',
                                                                                                   'category': 'hardening',
                                                                                                   'severity': 'medium',
                                                                                                   'title': 'Ensure '
                                                                                                            'that '
                                                                                                            'the '
                                                                                                            'eventRecordQPS '
                                                                                                            'argument '
                                                                                                            'is '
                                                                                                            'set '
                                                                                                            'to '
                                                                                                            'a '
                                                                                                            'level '
                                                                                                            'which '
                                                                                                            'ensures '
                                                                                                            'appropriate '
                                                                                                            'event '
                                                                                                            'capture',
                                                                                                   'remediation_hint': 'Set '
                                                                                                                       'eventRecordQPS '
                                                                                                                       'in '
                                                                                                                       'each '
                                                                                                                       'kubelet '
                                                                                                                       'configuration '
                                                                                                                       'to '
                                                                                                                       'at '
                                                                                                                       'least '
                                                                                                                       'the '
                                                                                                                       'organization’s '
                                                                                                                       'approved '
                                                                                                                       'minimum, '
                                                                                                                       'then '
                                                                                                                       'restart '
                                                                                                                       'kubelet.'},
 'k8s_service_external_traffic_policy_matches_required': {'resource_kind': 'service',
                                                          'category': 'network',
                                                          'severity': 'medium',
                                                          'title': 'LoadBalancer external traffic policy '
                                                                   'matches required value',
                                                          'remediation_hint': 'Set '
                                                                              'spec.externalTrafficPolicy to '
                                                                              'required_external_traffic_policy '
                                                                              '(Local or Cluster) on each '
                                                                              'selected LoadBalancer Service '
                                                                              'manifest.'},
 'k8s_ingress_ingress_has_any_associated_ingress_93579100f9': {'resource_kind': 'ingress',
                                                               'category': 'network',
                                                               'severity': 'medium',
                                                               'title': 'Checks whether a Kubernetes Ingress '
                                                                        'resource has any associated Ingress '
                                                                        'rules for routing traffic',
                                                               'remediation_hint': 'Add a spec.rules entry '
                                                                                   'with an explicit host '
                                                                                   'and HTTP path to the '
                                                                                   'Ingress manifest.'},
 'k8s_response_team_required_binding': {'resource_kind': 'rolebinding,clusterrolebinding',
                                        'category': 'least_privilege',
                                        'severity': 'medium',
                                        'title': 'Response team has required RBAC binding',
                                        'remediation_hint': 'Create a RoleBinding or ClusterRoleBinding for '
                                                            'the required response team subject and required '
                                                            'Role or ClusterRole within an allowed '
                                                            'namespace.'}}


def _inventory(index, kind):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'k8s':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    if not scope:
        raise Unavailable('snapshot scope missing')
    cluster = get(context, 'metadata.cluster_id', str)
    if not cluster:
        raise Unavailable('snapshot cluster identity missing')
    pages = get(index, 'collections', dict).get(kind)
    if not isinstance(pages, list) or not pages:
        raise Unavailable('dependency not collected: ' + kind)
    for page in pages:
        if not isinstance(page, dict) or page.get('scope') != scope or page.get('type') != kind or page.get('status') not in ('collected', 'empty'):
            raise Unavailable('incomplete or foreign-scope ' + kind + ' inventory')
        if page['status'] == 'empty' and get(page, 'items', list):
            raise Unavailable('empty inventory contains resources')
    wrappers = get(index, kind, list)
    for wrapper in wrappers:
        if get(wrapper, 'scope', str) != scope or get(wrapper, 'type', str) != kind:
            raise Unavailable('foreign-scope resource in ' + kind)
        if 'provider' in wrapper and get(wrapper, 'provider', str) != 'k8s':
            raise Unavailable('foreign-provider resource in ' + kind)
    rows = complete_items(index, kind)
    native = [item for page in pages for item in get(page, 'items', list)]
    try:
        if Counter(json.dumps(x, sort_keys=True) for x in rows) != Counter(json.dumps(x, sort_keys=True) for x in native):
            raise Unavailable('inventory content mismatch')
    except (TypeError, ValueError) as exc:
        raise Unavailable('inventory content malformed') from exc
    identities = set()
    namespaced = kind in {'pod', 'networkpolicy', 'service', 'ingress', 'rolebinding'}
    for row in rows:
        provenance = optional(row, 'provenance', {}, dict)
        if 'cluster_id' in provenance and get(provenance, 'cluster_id', str) != cluster:
            raise Unavailable('foreign cluster in ' + kind)
        if namespaced or kind in {'namespace', 'node', 'clusterrolebinding'}:
            name = get(row, 'metadata.name', str)
            namespace = get(row, 'metadata.namespace', str) if namespaced else None
            if not name or namespaced and not namespace:
                raise Unavailable('resource identity malformed in ' + kind)
            if not namespaced and optional(get(row, 'metadata', dict), 'namespace', None) not in (None, ''):
                raise Unavailable('cluster resource has a namespace')
            if scope != '*' and (namespaced and namespace != scope or kind == 'namespace' and name != scope):
                raise Unavailable('foreign namespace in ' + kind)
            identity = (namespace, name)
            if identity in identities:
                raise Unavailable('duplicate resource identity in ' + kind)
            identities.add(identity)
    return rows


def _member(item, index, kind):
    rows = _inventory(index, kind)
    if not any(row == item for row in rows):
        raise Unavailable('item not present in complete inventory')
    return rows


def _policy(index, key, expected):
    context = get(index, 'context', dict)
    meta = get(context, 'metadata', dict)
    policy = get(meta, 'compliance_policy', dict)
    if get(policy, 'status', str) != 'collected' or get(policy, 'cluster_id', str) != get(meta, 'cluster_id', str):
        raise Unavailable('operator policy unavailable or foreign cluster')
    if 'observed_at' in policy or 'max_age_seconds' in policy:
        observed = get(policy, 'observed_at', str)
        age = get(policy, 'max_age_seconds', int)
        capture = get(context, 'created_at', str)
        if not all(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)', value) for value in (observed, capture)):
            raise Unavailable('policy observation timestamp malformed')
        try:
            delta = (datetime.fromisoformat(capture.replace('Z', '+00:00')) - datetime.fromisoformat(observed.replace('Z', '+00:00'))).total_seconds()
        except ValueError as exc:
            raise Unavailable('policy observation timestamp malformed') from exc
        if age <= 0 or not 0 <= delta <= age:
            raise Unavailable('operator policy stale or future')
    return get(policy, key, expected)


def _attested_coverage(index, key):
    context = get(index, 'context', dict)
    meta = get(context, 'metadata', dict)
    coverage = get(meta, key, dict)
    if get(coverage, 'status', str) != 'attested_complete' or get(coverage, 'cluster_id', str) != get(meta, 'cluster_id', str):
        raise Unavailable('component coverage not attested complete')
    if get(coverage, 'node_count', int) <= 0 or get(coverage, 'max_age_seconds', int) <= 0:
        raise Unavailable('component coverage bounds malformed')
    observed, capture = get(coverage, 'observed_at', str), get(context, 'created_at', str)
    if not all(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)', value) for value in (observed, capture)):
        raise Unavailable('component coverage timestamp malformed')
    elapsed = (datetime.fromisoformat(capture.replace('Z', '+00:00')) - datetime.fromisoformat(observed.replace('Z', '+00:00'))).total_seconds()
    if not 0 <= elapsed <= coverage['max_age_seconds']:
        raise Unavailable('component coverage stale or future')


def _string_set(index, key):
    values = _policy(index, key, list)
    if not values or any(not isinstance(x, str) or len(x) > 63 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', x) and not (key == 'allowed_namespaces' and x == '*') for x in values) or len(values) != len(set(values)):
        raise Unavailable('operator string set malformed: ' + key)
    return set(values)


def _selector(index, key):
    value = _policy(index, key, dict)
    if not value or any(not _label_key(k) or not _label_value(v) for k, v in value.items()):
        raise Unavailable('operator selector malformed: ' + key)
    return value


def _label_key(value):
    if not isinstance(value, str) or len(value) > 253:
        return False
    prefix, sep, name = value.rpartition('/')
    return bool(name) and len(name) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?', name) is not None and (not sep or bool(prefix) and all(len(part) <= 63 and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', part) for part in prefix.split('.')))


def _label_value(value):
    return isinstance(value, str) and len(value) <= 63 and (not value or re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?', value) is not None)


def _labels(item, path):
    parent, key = path.rsplit('.', 1)
    obj = _native_optional(get(item, parent, dict), key, {}, dict, source=item)
    if any(not _label_key(k) or not _label_value(v) for k, v in obj.items()):
        raise Unavailable('labels malformed')
    return obj


def _full_native(item):
    return optional(optional(item, 'provenance', {}, dict), 'evidence', None, str) == 'read-only list'


def _native_optional(item, key, default, expected, *, source=None):
    if key in item or key in item.get('_coverage', {}):
        return get(item, key, expected)
    if _full_native(item if source is None else source):
        return default
    raise Unavailable('omitted field without full native list provenance: ' + key)


def _pod_name(item):
    name = get(item, 'metadata.name', str)
    namespace = get(item, 'metadata.namespace', str)
    if not name or not namespace:
        raise Unavailable('Pod identity malformed')
    return namespace, name


def _component(item, expected):
    spec = get(item, 'spec', dict)
    containers = get(spec, 'containers', list)
    if not containers or any(not isinstance(x, dict) for x in containers):
        raise Unavailable('Pod containers malformed')
    observed = []
    unresolved = False
    for container in containers:
        config = container.get('_component_config')
        if config is None:
            unresolved = True
            continue
        if not isinstance(config, dict):
            raise Unavailable('component projection malformed')
        component = get(config, 'component')
        if component not in (None, 'kube-apiserver', 'kube-controller-manager', 'kube-scheduler', 'kubelet', 'kube-proxy', 'etcd'):
            raise Unavailable('component identity malformed')
        if component is not None or config.get('component_identification') == 'ordinary_command':
            if get(config, 'flags_complete', bool) is not True:
                raise Unavailable('component flags incomplete')
        if component == expected:
            if get(config, 'flags_complete', bool) is not True:
                raise Unavailable('component flags incomplete')
            observed.append(config)
        elif component is None and config.get('component_identification') != 'ordinary_command':
            unresolved = True
    if unresolved:
        raise Unavailable('component inventory not proven complete')
    if not observed:
        return None
    if len(observed) != 1:
        raise Unavailable('ambiguous component declaration')
    return get(observed[0], 'flags', dict)


def _flag_list(flags, name):
    value = get(flags, name, str)
    if not value or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*', token) for token in value.split(',')):
        raise Unavailable('component flag list malformed')
    return set(value.split(','))


def _subjects(binding, binding_kind):
    subjects = _native_optional(binding, 'subjects', [], list)
    for subject in subjects:
        kind = get(subject, 'kind', str)
        name = get(subject, 'name', str)
        if kind not in ('User', 'Group', 'ServiceAccount') or not name:
            raise Unavailable('RBAC subject malformed')
        if kind == 'ServiceAccount':
            namespace = _native_optional(subject, 'namespace',
                                         get(binding, 'metadata.namespace', str) if binding_kind == 'rolebinding' else None,
                                         str, source=binding)
            if not namespace:
                raise Unavailable('ServiceAccount subject namespace unavailable')
    return subjects


def _duration_seconds(value):
    # Kubernetes duration flags use Go time.ParseDuration, including compounds
    # and fractions. Decimal arithmetic preserves comparisons at nanosecond precision.
    if value in ('0', '+0', '-0'):
        return Decimal(0)
    match = re.fullmatch(r'([+-]?)((?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:ns|us|ms|s|m|h))+)', value)
    if not match:
        raise Unavailable('request timeout malformed')
    units = {'ns': 1, 'us': 1000, 'ms': 1_000_000, 's': 1_000_000_000,
             'm': 60_000_000_000, 'h': 3_600_000_000_000}
    with localcontext() as precision:
        precision.prec = len(value) + 30
        nanoseconds = sum(int(Decimal(number) * units[unit]) for number, unit in re.findall(r'([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(ns|us|ms|s|m|h)', match[2]))
    if match[1] == '-':
        nanoseconds = -nanoseconds
    if not -(1 << 63) <= nanoseconds < (1 << 63):
        raise Unavailable('request timeout outside Go duration range')
    return Decimal(nanoseconds) / 1_000_000_000


def _pod_evaluator(check_id, item, index):
    _member(item, index, 'pod')
    namespace, name = _pod_name(item)
    if check_id == 'k8s_pod_secret_pod_rule_non_compliant_fcdc38e543':
        spec = get(item, 'spec', dict)
        # Full native LIST omits unset imagePullSecrets. A partial projection cannot prove absence.
        if 'imagePullSecrets' not in spec:
            if item.get('provenance', {}).get('evidence') != 'read-only list':
                return unknown('imagePullSecrets absent without full Pod representation')
            secrets = []
        else:
            secrets = get(spec, 'imagePullSecrets', list)
        if any(not isinstance(x, dict) or not isinstance(x.get('name'), str) for x in secrets):
            raise Unavailable('imagePullSecrets malformed')
        return result(not any(x['name'] for x in secrets), namespace=namespace, pod=name)
    if check_id in NAMESPACE_POD_IDS:
        allowed = _string_set(index, 'approved_namespaces')
        failed = namespace not in allowed
        if check_id == POD_NODE_POOL_ID:
            selector = _selector(index, 'approved_node_pool_selector')
            node_name = get(item, 'spec.nodeName', str)
            if not node_name:
                return unknown('Pod is not bound to a Node')
            nodes = _inventory(index, 'node')
            matches = [x for x in nodes if get(x, 'metadata.name', str) == node_name]
            if len(matches) != 1:
                return unknown('bound Node absent or ambiguous')
            labels = _labels(matches[0], 'metadata.labels')
            failed |= any(labels.get(k) != v for k, v in selector.items())
        if check_id == POD_NODE_SELECTOR_ID:
            selector = _selector(index, 'approved_node_selector')
            labels = _labels(item, 'spec.nodeSelector')
            failed |= any(labels.get(k) != v for k, v in selector.items())
        if check_id in (POD_LABEL_ID, POD_RUNNING_ID):
            selector = _selector(index, 'approved_label_selector')
            labels = _labels(item, 'metadata.labels')
            failed |= any(labels.get(k) != v for k, v in selector.items())
        if check_id == POD_RUNNING_ID:
            phase = get(item, 'status.phase', str)
            if phase not in {'Pending', 'Running', 'Succeeded', 'Failed', 'Unknown'}:
                raise Unavailable('Pod phase unrecognized')
            failed |= phase != 'Running'
        return result(failed, namespace=namespace, pod=name)
    if check_id == 'k8s_pod_serviceaccount_has_rbac_binding':
        spec = get(item, 'spec', dict)
        sa = _native_optional(spec, 'serviceAccountName', 'default', str, source=item)
        if not sa and _full_native(item):
            sa = 'default'
        if not sa:
            raise Unavailable('ServiceAccount name malformed')
        bindings = [(binding_kind, binding) for binding_kind in ('rolebinding', 'clusterrolebinding')
                    for binding in _inventory(index, binding_kind)]
        matched = False
        for binding_kind, binding in bindings:
                binding_ns = get(binding, 'metadata.namespace', str) if binding_kind == 'rolebinding' else None
                subjects = _subjects(binding, binding_kind)
                for subject in subjects:
                    if not isinstance(subject, dict):
                        raise Unavailable('RBAC subject malformed')
                    kind = get(subject, 'kind', str)
                    subject_name = get(subject, 'name', str)
                    if kind == 'ServiceAccount':
                        subject_ns = _native_optional(subject, 'namespace', binding_ns, str, source=binding)
                        if subject_ns == namespace and subject_name == sa and (binding_ns is None or binding_ns == namespace):
                            matched = True
        return result(not matched, namespace=namespace, pod=name, service_account=sa)
    if check_id == 'k8s.cis.consider_external_secret_storage':
        spec = get(item, 'spec', dict)
        if not _full_native(item):
            return unknown('full PodSpec provenance unavailable')
        volumes = optional(spec, 'volumes', [], list)
        containers = get(spec, 'containers', list)
        if not containers or any(not isinstance(x, dict) for x in containers):
            raise Unavailable('Pod containers malformed')
        secret = False
        csi = False
        for volume in volumes:
            if not isinstance(volume, dict):
                raise Unavailable('volume malformed')
            if 'secret' in volume:
                if not get(volume, 'secret.secretName', str):
                    raise Unavailable('Secret name malformed')
                secret = True
            if 'csi' in volume:
                driver = get(volume, 'csi.driver', str)
                if not driver:
                    raise Unavailable('CSI driver malformed')
                csi |= driver == 'secrets-store.csi.k8s.io'
            for key in ('secret', 'csi'):
                if key in volume.get('_coverage', {}):
                    get(volume, key, dict)
        for container in containers:
            for entry in optional(container, 'env', [], list):
                if not isinstance(entry, dict):
                    raise Unavailable('environment entry malformed')
                if 'valueFrom' in entry or 'valueFrom' in entry.get('_coverage', {}):
                    source = get(entry, 'valueFrom', dict)
                    if 'secretKeyRef' in source or 'secretKeyRef' in source.get('_coverage', {}):
                        if not get(source, 'secretKeyRef.name', str):
                            raise Unavailable('Secret name malformed')
                        secret = True
            for entry in optional(container, 'envFrom', [], list):
                if not isinstance(entry, dict):
                    raise Unavailable('environment source malformed')
                if 'secretRef' in entry or 'secretRef' in entry.get('_coverage', {}):
                    if not get(entry, 'secretRef.name', str):
                        raise Unavailable('Secret name malformed')
                    secret = True
        if not secret:
            return 'NOT_APPLICABLE', {'reason': 'Pod declares no native Secret reference'}
        return result(not csi, namespace=namespace, pod=name, semantics='Pod declaration only')
    component = COMPONENT_POD_IDS.get(check_id)
    if component:
        flags = _component(item, component)
        if flags is None:
            return 'NOT_APPLICABLE', {'reason': 'Pod has no applicable component declaration'}
        if check_id == 'k8s.cis.controller_manager_rotate_kubelet_server_certificate_true':
            gates = get(flags, 'feature-gates', str)
            pairs = dict()
            for token in gates.split(','):
                key, sep, value = token.partition('=')
                if not sep or not key or value not in ('true', 'false') or key in pairs:
                    raise Unavailable('feature gates malformed')
                pairs[key] = value
            if 'RotateKubeletServerCertificate' not in pairs:
                return unknown('RotateKubeletServerCertificate declaration missing')
            return result(pairs['RotateKubeletServerCertificate'] != 'true')
        if check_id == 'k8s.cis.the_service_account_extend_token_expiration_parameter_is_set_to_false':
            value = get(flags, 'service-account-extend-token-expiration', str)
            if value not in ('true', 'false'):
                raise Unavailable('boolean component flag malformed')
            return result(value != 'false')
        if check_id == 'k8s.cis.the_request_timeout_argument_is_set_as_appropriate':
            maximum = _policy(index, 'approved_max_request_timeout', int)
            if not 0 < maximum < (1 << 63):
                raise Unavailable('approved timeout malformed')
            value = get(flags, 'request-timeout', str)
            seconds = _duration_seconds(value)
            return result(not 0 < seconds <= maximum, seconds=float(seconds), approved_max_seconds=maximum)
        if check_id == 'k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost':
            if get(get(index, 'context', dict), 'scope', str) != '*':
                raise Unavailable('kube-proxy requires cluster-wide Pod coverage')
            _attested_coverage(index, 'kube_proxy_pod_coverage')
            value = get(flags, 'metrics-bind-address', str)
            endpoint = re.fullmatch(r'(?:\[([^\[\]]+)\]|([^:\[\]]+)):([0-9]+)', value)
            if not endpoint:
                raise Unavailable('metrics bind address malformed')
            try:
                host = endpoint[1] or endpoint[2]
                port = int(endpoint[3])
                ip = ipaddress.ip_address(host)
            except (ValueError, IndexError) as exc:
                raise Unavailable('metrics bind address malformed') from exc
            if not 0 <= port <= 65535:
                raise Unavailable('metrics bind port malformed')
            return result(str(ip) not in ('127.0.0.1', '::1'), address=value)
        if check_id == 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller':
            enabled = _flag_list(flags, 'enable-admission-plugins')
            disabled = _flag_list(flags, 'disable-admission-plugins')
            if 'ImagePolicyWebhook' not in enabled or 'ImagePolicyWebhook' in disabled:
                return result(True, reason='ImagePolicyWebhook disabled in explicit flags')
            path = get(flags, 'admission-control-config-file', str)
            if not path.startswith('/') or not path.strip():
                return result(True, reason='admission control config path invalid')
            return unknown('admission control file content has not been verified')
    raise Unavailable('unhandled Pod check')


def _networkpolicy_evaluator(check_id, item, index):
    _member(item, index, 'networkpolicy')
    spec = get(item, 'spec', dict)
    if check_id == 'k8s_networkpolicy_has_ingress_rules':
        rules = _native_optional(spec, 'ingress', [], list, source=item)
        if any(not isinstance(x, dict) for x in rules):
            raise Unavailable('ingress rules malformed')
        return result(len(rules) == 0, ingress_rule_count=len(rules))
    if check_id == 'k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c':
        selector = get(spec, 'podSelector', dict)
        labels = _native_optional(selector, 'matchLabels', {}, dict, source=item)
        expressions = _native_optional(selector, 'matchExpressions', [], list, source=item)
        if any(not _label_key(k) or not _label_value(v) for k, v in labels.items()):
            raise Unavailable('matchLabels malformed')
        for expression in expressions:
            key = get(expression, 'key', str)
            operator = get(expression, 'operator', str)
            if not _label_key(key) or operator not in ('In', 'NotIn', 'Exists', 'DoesNotExist'):
                raise Unavailable('matchExpressions malformed')
            values = _native_optional(expression, 'values', [], list, source=item)
            if any(not _label_value(value) for value in values) or (operator in ('In', 'NotIn')) != bool(values):
                raise Unavailable('matchExpressions values malformed')
        return result(not labels and not expressions)
    raise Unavailable('unhandled NetworkPolicy check')


def _scope_evaluator(check_id, item, index):
    if get(item, 'scope', str) != get(get(index, 'context', dict), 'scope', str):
        raise Unavailable('foreign scope target')
    if check_id in VERSION_IDS:
        rows = _inventory(index, 'api_discovery')
        if len(rows) != 1:
            raise Unavailable('API discovery ambiguous')
        observed = get(rows[0], 'serverVersion.gitVersion', str)
        oldest = _policy(index, 'oldestVersionSupported', str)
        def semver(value):
            match = re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?', value)
            if not match or len(value) > 253 or match[5] is not None and any(not part for part in match[5].split('.')):
                raise Unavailable('Kubernetes semver malformed')
            prerelease = match[4]
            if prerelease is None:
                suffix = (1, ())
            else:
                parts = prerelease.split('.')
                if any(not part or part.isdigit() and len(part) > 1 and part[0] == '0' for part in parts):
                    raise Unavailable('Kubernetes semver prerelease malformed')
                suffix = (0, tuple((0, int(part)) if part.isdigit() else (1, part) for part in parts))
            return tuple(map(int, match.groups()[:3])) + suffix
        current, floor = semver(observed), semver(oldest)
        return result(current < floor if check_id.endswith('at_least_oldest_supported') else current <= floor, observed=observed, oldest=oldest)
    if check_id == 'k8s_response_team_required_binding':
        namespaces = _string_set(index, 'allowed_namespaces')
        subject_kind = _policy(index, 'required_subject_kind', str)
        subject_name = _policy(index, 'required_subject_name', str)
        role_kind = _policy(index, 'required_role_kind', str)
        role_name = _policy(index, 'required_role_name', str)
        if subject_kind not in ('User', 'Group', 'ServiceAccount') or role_kind not in ('Role', 'ClusterRole') or any(not 0 < len(value) <= 253 or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:@/-]*', value) is None for value in (subject_name, role_name)):
            raise Unavailable('required binding policy malformed')
        bindings = [(binding_kind, row) for binding_kind in ('rolebinding', 'clusterrolebinding')
                    for row in _inventory(index, binding_kind)]
        matched = False
        for binding_kind, row in bindings:
                binding_ns = get(row, 'metadata.namespace', str) if binding_kind == 'rolebinding' else '*'
                role = (get(row, 'roleRef.kind', str), get(row, 'roleRef.name', str))
                if role[0] not in ('Role', 'ClusterRole') or not role[1] or binding_kind == 'clusterrolebinding' and role[0] != 'ClusterRole':
                    raise Unavailable('RBAC role reference malformed')
                subjects = _subjects(row, binding_kind)
                for subject in subjects:
                    if not isinstance(subject, dict):
                        raise Unavailable('subject malformed')
                    kind = get(subject, 'kind', str)
                    name = get(subject, 'name', str)
                    if binding_ns in namespaces and role == (role_kind, role_name) and kind == subject_kind and name == subject_name:
                        matched = True
        return result(not matched)
    raise Unavailable('unhandled scope check')


def _resource_evaluator(check_id, item, index):
    kind = SPECS[check_id]['resource_kind']
    if kind == 'pod':
        return _pod_evaluator(check_id, item, index)
    if kind == 'networkpolicy':
        return _networkpolicy_evaluator(check_id, item, index)
    if kind == 'namespace':
        _member(item, index, 'namespace')
        name = get(item, 'metadata.name', str)
        if not name:
            raise Unavailable('Namespace identity malformed')
        if check_id == 'k8s.cis.namespace_has_networkpolicy':
            system = _string_set(index, 'system_namespaces')
            if name in system:
                return 'NOT_APPLICABLE', {'reason': 'configured system namespace'}
            policies = _inventory(index, 'networkpolicy')
            names = [get(row, 'metadata.namespace', str) for row in policies]
            return result(name not in names, namespace=name)
    if kind == 'component_configuration':
        _member(item, index, 'component_configuration')
        if check_id == 'k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture':
            if get(item, 'component', str) != 'kubelet':
                return 'NOT_APPLICABLE', {'reason': 'not kubelet configuration'}
            _attested_coverage(index, 'component_configuration_coverage')
            threshold = _policy(index, 'approved_min_event_qps', int)
            if not 0 <= threshold < (1 << 63):
                raise Unavailable('event QPS threshold malformed')
            qps = get(item, 'configuration.eventRecordQPS', int)
            if not 0 <= qps < (1 << 31):
                raise Unavailable('event QPS declaration malformed')
            return result(qps < threshold, observed=qps, required=threshold)
    if kind == 'clusterrolebinding':
        _member(item, index, 'clusterrolebinding')
        if check_id == 'k8s.cis.avoid_use_of_system_masters_group':
            all_bindings = _inventory(index, 'clusterrolebinding') + _inventory(index, 'rolebinding')
            for binding in all_bindings:
                for subject in optional(binding, 'subjects', [], list):
                    if not isinstance(subject, dict):
                        raise Unavailable('RBAC subject malformed')
                    if get(subject, 'kind', str) == 'Group' and get(subject, 'name', str) == 'system:masters':
                        return result(True, reason='observed binding to system:masters')
            return unknown('certificate and provider identity group membership not observed')
    if kind == 'service':
        _member(item, index, 'service')
        if check_id == 'k8s_service_external_traffic_policy_matches_required':
            names = _string_set(index, 'in_scope_service_names')
            required = _policy(index, 'required_external_traffic_policy', str)
            if required not in ('Cluster', 'Local'):
                raise Unavailable('external traffic policy malformed')
            name = get(item, 'metadata.name', str)
            spec = get(item, 'spec', dict)
            service_type = _native_optional(spec, 'type', 'ClusterIP', str, source=item)
            if service_type not in ('ClusterIP', 'NodePort', 'LoadBalancer', 'ExternalName'):
                raise Unavailable('Service type unrecognized')
            if name not in names or service_type != 'LoadBalancer':
                return 'NOT_APPLICABLE', {'reason': 'Service outside selected LoadBalancer set'}
            observed = _native_optional(spec, 'externalTrafficPolicy', 'Cluster', str, source=item)
            if observed not in ('Cluster', 'Local'):
                raise Unavailable('external traffic policy unrecognized')
            return result(observed != required, observed=observed, required=required)
    if kind == 'ingress':
        _member(item, index, 'ingress')
        if check_id == 'k8s_ingress_ingress_has_any_associated_ingress_93579100f9':
            rules = _native_optional(get(item, 'spec', dict), 'rules', [], list, source=item)
            if any(not isinstance(row, dict) for row in rules):
                raise Unavailable('Ingress rules malformed')
            return result(len(rules) == 0, rule_count=len(rules))
    raise Unavailable('unhandled check')

POD_NODE_POOL_ID = 'k8s_pod_pod_deployed_specific_namespace_its_76714f9dfe'
POD_NODE_SELECTOR_ID = 'k8s_pod_pod_deployed_within_specific_namespace_3790c81f90'
POD_LABEL_ID = 'k8s_pod_pod_deployed_within_specific_namespace_62bb9e62c0'
POD_RUNNING_ID = 'k8s_pod_pod_running_within_specific_namespace_0f3d581358'
NAMESPACE_POD_IDS = {POD_NODE_POOL_ID, 'k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b', POD_NODE_SELECTOR_ID, POD_LABEL_ID, POD_RUNNING_ID}
COMPONENT_POD_IDS = {
    'k8s.cis.controller_manager_rotate_kubelet_server_certificate_true': 'kube-controller-manager',
    'k8s.cis.the_service_account_extend_token_expiration_parameter_is_set_to_false': 'kube-apiserver',
    'k8s.cis.the_request_timeout_argument_is_set_as_appropriate': 'kube-apiserver',
    'k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost': 'kube-proxy',
    'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller': 'kube-apiserver',
}
VERSION_IDS = {'k8s_cluster_version_at_least_oldest_supported', 'k8s_cluster_version_supported'}

DEPENDENCIES = {
    POD_NODE_POOL_ID: ['pod', 'node'],
    'k8s_pod_serviceaccount_has_rbac_binding': ['pod', 'rolebinding', 'clusterrolebinding'],
    'k8s.cis.namespace_has_networkpolicy': ['namespace', 'networkpolicy'],
    'k8s.cis.avoid_use_of_system_masters_group': ['clusterrolebinding', 'rolebinding'],
    'k8s_response_team_required_binding': ['rolebinding', 'clusterrolebinding'],
}

for _id, _spec in SPECS.items():
    _kind = _spec['resource_kind']
    _target = 'scope' if _id in VERSION_IDS or _id == 'k8s_response_team_required_binding' else 'resource'
    _dependencies = DEPENDENCIES.get(_id, [_kind])
    @register(_id, 'k8s', _spec['category'], _kind, _spec['title'], _spec['severity'],
              'CM-6', _spec['remediation_hint'], target=_target, dependencies=_dependencies)
    def _evaluate(item, index, check_id=_id, target=_target):
        return _scope_evaluator(check_id, item, index) if target == 'scope' else _resource_evaluator(check_id, item, index)
