"""Unregistered successors for five native, redacted annotation predicates.

Root admits these atomically with source/copy/fixture successors. Importing this
module does not register checks or alter historical CASES or annotations.
"""
import re
from urllib.parse import quote

from peaso.collectors.k8s_annotation_indicators_20261020 import (
    MARKER, CONTEXT, SCHEMA, FLAGS, TYPES, MAX_ANNOTATIONS, digest, identity)

INGRESS_IDS = tuple('k8s.claude.ingress.' + suffix for suffix in
    ('no_nginx_snippets', 'no_nginx_snippet_alias', 'no_nginx_snippet_lua'))
PSP_IDS = tuple('k8s.claude.podsecuritypolicy.' + suffix for suffix in
    ('default_seccomp_profile', 'security_services_hardening'))
IDS = INGRESS_IDS + PSP_IDS


def _native_flags(item, index, kind):
    context = index['context']
    scope = context['scope']; cluster = context['metadata']['cluster_id']
    receipt = context['metadata'][CONTEXT]
    if (context['provider'] != 'k8s' or receipt['schema'] != SCHEMA or receipt['provider'] != 'k8s'
            or receipt['cluster_id'] != cluster or not isinstance(cluster, str) or not cluster
            or receipt['authentication'] not in ('configured_bearer', 'configured_client_certificate')
            or re.fullmatch('[0-9a-f]{64}', receipt['origin_digest']) is None
            or re.fullmatch('[0-9a-f]{32}', receipt['session']) is None):
        raise ValueError('authenticated annotation context unresolved')
    own, = [r for r in index['collections'][kind] if r.get('scope') == scope]
    if (own['type'] != kind or own['service'] != 'kubernetes' or own['status'] != 'collected'
            or own.get('error') or sum(r == item for r in own['items']) != 1):
        raise ValueError('annotation inventory incomplete or unbound')
    version, typ = TYPES[kind]
    values = identity(item)
    api_version, native_kind, namespace, name, uid, rv = values
    if api_version not in (None, version) or native_kind not in (None, typ):
        raise ValueError('native annotation type conflicts')
    if kind == 'ingress' and (not namespace or scope != '*' and namespace != scope):
        raise ValueError('native annotation namespace conflicts')
    if kind == 'podsecuritypolicy' and namespace not in (None, ''):
        raise ValueError('cluster annotation object has namespace')
    marker = item[MARKER]
    if (set(marker) != {'schema', 'status', 'identity_digest', 'flags', 'annotation_count', 'source'}
            or marker['schema'] != SCHEMA or marker['status'] != 'bound'
            or marker['identity_digest'] != digest(values)
            or type(marker['annotation_count']) is not int or not 0 <= marker['annotation_count'] <= MAX_ANNOTATIONS
            or set(marker['flags']) != set(FLAGS) or any(type(v) is not bool for v in marker['flags'].values())):
        raise ValueError('annotation projection incomplete')
    expected_path = ('/apis/networking.k8s.io/v1/' +
        ('' if scope == '*' else 'namespaces/' + quote(scope, safe='') + '/') + 'ingresses'
        if kind == 'ingress' else '/apis/policy/v1beta1/podsecuritypolicies')
    native_id = 'k8s://' + '/'.join(quote(str(v), safe='') for v in
        (cluster, kind, namespace if kind == 'ingress' else '_cluster', uid))
    if marker['source'] != {'method': 'GET', 'path': expected_path, 'kind': kind, 'scope': scope,
            'context_digest': digest(receipt), 'native_id': native_id, 'native_type': typ, 'native_api_version': version} or item['id'] != native_id:
        raise ValueError('annotation request identity conflicts')
    provenance = item['provenance']
    if (provenance['cluster_id'] != cluster or provenance['evidence'] != 'read-only list'
            or provenance['uid'] != uid or provenance['resourceVersion'] != rv
            or provenance.get('namespace') != (namespace if kind == 'ingress' else '_cluster')
            or provenance.get('apiVersion') != api_version
            or provenance.get('representation') is not None):
        raise ValueError('annotation native producer provenance conflicts')
    return marker['flags']


def evaluate(check_id, item, index):
    try:
        if check_id not in IDS:
            raise ValueError('unreviewed annotation criterion')
        kind = 'ingress' if check_id in INGRESS_IDS else 'podsecuritypolicy'
        flags = _native_flags(item, index, kind)
        if kind == 'ingress':
            field = dict(zip(INGRESS_IDS, ('snippet', 'alias', 'lua')))[check_id]
            hit = flags[field]
            observed = ('The native Ingress declares a matching snippet annotation indicator. Annotation text was redacted; controller execution was not tested.' if hit else
                'The complete native Ingress annotation map contains no matching snippet indicator. Annotation text was redacted; controller behavior was not tested.')
            return ('FAIL' if hit else 'PASS'), {'observed': observed, 'indicator': field, 'matched': hit,
                'scope': 'native_declared_annotation_pattern_only', 'annotation_content_retained': False}
        own_version = item['_provenance']['kubernetes_version']
        discovery, = [r for r in index['collections']['api_discovery'] if r.get('scope') == index['context']['scope']]
        discovered, = discovery['items']
        if (discovery['type'] != 'api_discovery' or discovery['status'] != 'collected'
                or discovered['provenance']['cluster_id'] != index['context']['metadata']['cluster_id']
                or discovered['provenance']['source'] != 'GET /apis'
                or discovered.get('podSecurityPolicyAdvertised') is not True
                or discovered.get('_coverage', {}).get('podSecurityPolicyAdvertised')
                or discovered.get('_coverage', {}).get('serverVersion') or discovered['serverVersion']['gitVersion'] != own_version):
            raise ValueError('legacy version discovery unbound')
        match = re.fullmatch(r'v?(\d+)\.(\d+)\.\d+(?:[-+][A-Za-z0-9.-]+)?', own_version)
        if not match or tuple(map(int, match.groups())) >= (1, 25):
            raise ValueError('legacy PSP version unresolved or removed')
        if not isinstance(item['spec'], dict):
            raise ValueError('legacy PSP spec unavailable')
        if check_id == PSP_IDS[0]:
            good = flags['seccomp_runtime_default']
            observed = ('The legacy PSP declares a recognized runtime default seccomp profile.' if good else
                        'The legacy PSP does not declare a recognized runtime default seccomp profile.')
        else:
            se_linux = item['spec'].get('seLinux', {})
            if not isinstance(se_linux, dict) or se_linux.get('rule') not in (None, 'RunAsAny', 'MustRunAs'):
                raise ValueError('legacy SELinux rule malformed')
            good = se_linux.get('rule') == 'MustRunAs' or flags['apparmor_runtime_default'] or flags['seccomp_runtime_default']
            observed = ('The legacy PSP declares SELinux MustRunAs or a recognized AppArmor/seccomp default.' if good else
                        'The legacy PSP declares none of the reviewed SELinux, AppArmor or seccomp defaults.')
        return ('PASS' if good else 'FAIL'), {'observed': observed + ' This is legacy policy configuration; bindings and runtime enforcement are separate.',
            'scope': 'legacy_native_policy_configuration_only', 'annotation_content_retained': False}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return 'UNKNOWN', {'observed': 'The native annotation map, identity, authenticated read context or complete inventory could not be bound. Annotation absence could not be assessed.'}


DECLARATIONS = [{'id': cid, 'provider': 'k8s', 'kind': 'ingress' if cid in INGRESS_IDS else 'podsecuritypolicy',
    'category': 'hardening', 'existing_ui_group': 'unchanged', 'registered': False,
    'dependencies': ['ingress'] if cid in INGRESS_IDS else ['podsecuritypolicy'],
    'source_decision': 'Successor for existing ID; no new runtime/control claim or numbered mapping.'} for cid in IDS]


def evaluate_for(check_id):
    if check_id not in IDS:
        raise ValueError('unreviewed annotation criterion')
    def evaluate_selected(item, index):
        return evaluate(check_id, item, index)
    return evaluate_selected
