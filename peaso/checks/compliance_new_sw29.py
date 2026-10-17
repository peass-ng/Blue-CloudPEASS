"""Signed Azure second-wave checks; conservative offline evidence evaluation."""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get

SPECS = {'azure.cis.legacy_infrastructure_double_encryption_postgresql_single_server': {'category': 'encryption',
                                                                                'proposed_spec_sha256': '87ad424bbef701ca1e75beeab786d698590dbc4dfd8b884688a8d75ea68c1f15',
                                                                                'provider': 'azure',
                                                                                'remediation_hint': 'Migrate '
                                                                                                    'legacy '
                                                                                                    'PostgreSQL '
                                                                                                    'Single '
                                                                                                    'Server '
                                                                                                    'to '
                                                                                                    'Flexible '
                                                                                                    'Server '
                                                                                                    'with '
                                                                                                    'infrastructure '
                                                                                                    'encryption '
                                                                                                    'enabled; '
                                                                                                    'for '
                                                                                                    'existing '
                                                                                                    'Single '
                                                                                                    'Server, '
                                                                                                    'use ARM '
                                                                                                    'server '
                                                                                                    'settings '
                                                                                                    'if the '
                                                                                                    'service '
                                                                                                    'still '
                                                                                                    'permits '
                                                                                                    'changes.',
                                                                                'resource_kind': 'postgresql_single_server',
                                                                                'severity': 'high',
                                                                                'title': 'Ensure '
                                                                                         "'Infrastructure "
                                                                                         "double encryption' "
                                                                                         'for PostgreSQL '
                                                                                         'Database Server is '
                                                                                         "'Enabled'"},
 'azure.cis.postgresql_single_log_retention_days': {'category': 'recovery',
                                                    'proposed_spec_sha256': 'c231feb6858dd2d3219d2bd93d72c9b0e8088bb85d31bb67dab506d30125e8e7',
                                                    'provider': 'azure',
                                                    'remediation_hint': 'Set PostgreSQL Single Server '
                                                                        'parameter log_retention_days to 4 '
                                                                        'or more in Server parameters or az '
                                                                        'postgres server configuration set.',
                                                    'resource_kind': 'postgresql_single_server',
                                                    'severity': 'medium',
                                                    'title': "Ensure Server Parameter 'log_retention_days' "
                                                             'is greater than 3 days for PostgreSQL Database '
                                                             'Server'},
 'azure.cis.postgresql_single_ssl_enforcement': {'category': 'encryption',
                                                 'proposed_spec_sha256': '2ddf6b921932af6b292a918ec7bbbaf1d1219b71863adb9373d7ca5017b020c2',
                                                 'provider': 'azure',
                                                 'remediation_hint': 'Azure portal > Azure Database for '
                                                                     'PostgreSQL Single Server > Connection '
                                                                     'security: Set sslEnforcement to '
                                                                     'Enabled on the legacy server.',
                                                 'resource_kind': 'postgresql_single_server',
                                                 'severity': 'medium',
                                                 'title': 'Legacy PostgreSQL single server enforces SSL'},
 'azure.other.gateway_affinity_cookie_timeout': {'category': 'hardening',
                                                 'proposed_spec_sha256': 'c99c34e728e25b1d77a04a12cdcc76c00f7eecf94dd86b8a91a3b96976469f29',
                                                 'provider': 'azure',
                                                 'remediation_hint': 'Disable affinity or implement a '
                                                                     'session idle timeout of at most 30 '
                                                                     'minutes, then verify expiration with a '
                                                                     'controlled idle-session probe.',
                                                 'resource_kind': 'application_gateway',
                                                 'severity': 'medium',
                                                 'title': 'Gateway affinity cookie expires within 30 '
                                                          'minutes'},
 'azure.other.gateway_client_rate_limit': {'category': 'hardening',
                                           'proposed_spec_sha256': 'f4a972b9bef4298502d800931b0a525ed837f258b6d07962c7d73066ec6ec2b5',
                                           'provider': 'azure',
                                           'remediation_hint': 'Configure an effective client-IP rate-limit '
                                                               'rule at 2000 requests per five minutes, then '
                                                               'verify that excess requests are throttled '
                                                               'for at least 60 seconds.',
                                           'resource_kind': 'application_gateway',
                                           'severity': 'high',
                                           'title': 'Limit client request rates at Application Gateway'},
 'azure.other.gateway_server_header_rewrite': {'category': 'hardening',
                                               'proposed_spec_sha256': 'da5ecf41062a53db2ef593d97db8f30192b4e953772f24fc0197a3fc6a9fde8c',
                                               'provider': 'azure',
                                               'remediation_hint': 'Apply a Server response-header rewrite '
                                                                   'with value lb to every Application '
                                                                   'Gateway routing path and verify live '
                                                                   'responses.',
                                               'resource_kind': 'application_gateway',
                                               'severity': 'medium',
                                               'title': 'Gateway rewrites Server response header'},
 'azure.other.gateway_throttle_log_alert': {'category': 'monitoring',
                                            'proposed_spec_sha256': '3b3591febf858a9a9e78c872e25b6f4bb4e96ba1e76c216f6ef6fed60f804546',
                                            'provider': 'azure',
                                            'remediation_hint': 'Enable ApplicationGatewayAccessLog export, '
                                                                'preserve throttling invocation and '
                                                                'ingestion timestamps, and correct log '
                                                                'delivery so each event is recorded within '
                                                                'five minutes; add alerting for trend '
                                                                'analysis.',
                                            'resource_kind': 'application_gateway',
                                            'severity': 'medium',
                                            'title': 'Gateway throttle events are logged promptly'},
 'azure.other.lb_certificate_auto_renew': {'category': 'encryption',
                                           'proposed_spec_sha256': '6d2e6ca67bd0d71ee2aa562a2a2c21d25e776e801a673743f4155d24e3904696',
                                           'provider': 'azure',
                                           'remediation_hint': 'Configure Key Vault renewal, bind a '
                                                               'versionless certificate secret URI, and '
                                                               'verify a new certificate version was '
                                                               'deployed on the Application Gateway listener '
                                                               'within 24 hours of the renewal trigger.',
                                           'resource_kind': 'application_gateway',
                                           'severity': 'high',
                                           'title': 'Application Gateway certificates have Key Vault '
                                                    'auto-renewal'},
 'azure.other.ml_public_access_exception': {'category': 'network',
                                            'proposed_spec_sha256': 'd9857d785ff840d21fc47a42c2fe71f54600c0c3f456afa223e863b008c97388',
                                            'provider': 'azure',
                                            'remediation_hint': 'Azure Machine Learning workspace > Compute: '
                                                                'disable node public IP; if an approved '
                                                                'exception is needed, document expiry and '
                                                                'restrict the compute subnet/NIC NSG to '
                                                                'approved sources and ports.',
                                            'resource_kind': 'ml_compute',
                                            'severity': 'high',
                                            'title': 'ML public access requires safeguards'},
 'azure.other.ml_root_exception': {'category': 'hardening',
                                   'proposed_spec_sha256': '8ba7a447536d104b990544487ce1cd153ff780ce8cc8636060499e09d517155b',
                                   'provider': 'azure',
                                   'remediation_hint': 'Disable root access on the affected ML development '
                                                       'environment, or document necessity and obtain a '
                                                       'time-bounded authorization tied to that instance.',
                                   'resource_kind': 'ml_compute',
                                   'severity': 'high',
                                   'title': 'ML root access has an approved exception'},
 'azure.other.ml_sensitive_subnet_allowlist': {'category': 'network',
                                               'proposed_spec_sha256': 'f0ad7bd1ec6bafde4f624df7c90bc33289aef7e72ee41c42efd90933b7cf433d',
                                               'provider': 'azure',
                                               'remediation_hint': 'Place sensitive AML compute in an '
                                                                   'approved subnet and apply the required '
                                                                   'NSG, route and access controls; verify '
                                                                   'the effective network baseline.',
                                               'resource_kind': 'ml_compute',
                                               'severity': 'high',
                                               'title': 'Sensitive ML compute uses approved networks'},
 'azure.other.ml_subnet_baseline': {'category': 'network',
                                    'proposed_spec_sha256': '71ab89629383880a3b42b2915fb4004b04b78bf171559cc6e34718980b15a699',
                                    'provider': 'azure',
                                    'remediation_hint': 'Place each non-sensitive MLDE instance on a subnet '
                                                        'that meets the approved network baseline; configure '
                                                        'its NSG, routes and other required controls, then '
                                                        'verify effective access.',
                                    'resource_kind': 'ml_compute',
                                    'severity': 'high',
                                    'title': 'Azure ML compute subnets have an approved NSG'},
 'azure.other.ml_terminal_exception': {'category': 'hardening',
                                       'proposed_spec_sha256': '9249f6b8f73146bbb20d071109cca388277c5bf6ee02f7f9e7152c4b061fd33e',
                                       'provider': 'azure',
                                       'remediation_hint': 'Restrict AML Studio terminal access through '
                                                           'effective workspace/compute permissions, disable '
                                                           'access where possible, and record scoped '
                                                           'time-limited authorization for necessary '
                                                           'sessions.',
                                       'resource_kind': 'ml_compute',
                                       'severity': 'high',
                                       'title': 'Require an approved exception for Azure ML SSH'},
 'azure_application_gateway_1_2_5_8_33a9d21': {'category': 'encryption',
                                               'proposed_spec_sha256': '8ecbe325c6c47c07de1308b01ae2a67924752f0e502036b829a8687d8046b288',
                                               'provider': 'azure',
                                               'remediation_hint': 'Set an approved custom TLS protocol and '
                                                                   'cipher policy on each Application '
                                                                   'Gateway HTTPS listener and approved '
                                                                   'Front Door HTTPS policy.',
                                               'resource_kind': 'application_gateway',
                                               'severity': 'medium',
                                               'title': 'Application Gateway HTTPS listeners use approved '
                                                        'TLS policies'},
 'azure_application_gateway_app_client_certificates_on_fcca0b8': {'category': 'encryption',
                                                                  'proposed_spec_sha256': 'b19af123f1080d40ec0b6d0f45e6703f83f83da0d65f6a62010b4335fac30446',
                                                                  'provider': 'azure',
                                                                  'remediation_hint': 'Bind a valid, trusted '
                                                                                      'Key Vault-backed TLS '
                                                                                      'certificate to each '
                                                                                      'HTTPS listener and '
                                                                                      'ensure the gateway '
                                                                                      'identity can read it.',
                                                                  'resource_kind': 'application_gateway',
                                                                  'severity': 'medium',
                                                                  'title': 'Application Gateway HTTPS '
                                                                           'listeners use Key Vault-backed '
                                                                           'server certificates'}}


_ARM = re.compile(r'^/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/([^/]+)/(.+)$', re.I)
_KINDS = {'ml_compute': ('Microsoft.MachineLearningServices', r'workspaces/[^/]+/computes/[^/]+'),
          'application_gateway': ('Microsoft.Network', r'applicationGateways/[^/]+'),
          'postgresql_single_server': ('Microsoft.DBforPostgreSQL', r'servers/[^/]+')}


def _instant(value):
    if not isinstance(value, str):
        raise Unavailable('timestamp missing or malformed')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.utcoffset() is None:
            raise ValueError('timezone required')
        return parsed
    except ValueError as exc:
        raise Unavailable('timestamp missing or malformed') from exc


def _inventory(index, kind, item):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'azure':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    if not re.fullmatch(r'/subscriptions/[^/]+', scope, re.I):
        raise Unavailable('malformed subscription scope')
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('inventory scope missing or ambiguous')
    envelope = envelopes[0]
    if get(envelope, 'type', str) != kind or get(envelope, 'scope', str).casefold() != scope.casefold():
        raise Unavailable('foreign inventory scope')
    rows = complete_items(index, kind)
    raw = get(index, kind, list)
    native = get(envelope, 'items', list)
    if len(raw) != len(rows) or len(native) != len(rows) or (get(envelope, 'status', str) == 'empty') != (not rows):
        raise Unavailable('inventory count or coverage conflict')
    seen = set()
    for wrapper, row, original in zip(raw, rows, native):
        rid = get(row, 'id', str)
        match = _ARM.fullmatch(rid)
        provider, suffix = _KINDS[kind]
        if (not match or ('/subscriptions/' + match.group(1)).casefold() != scope.casefold()
                or match.group(2).casefold() != provider.casefold()
                or not re.fullmatch(suffix, match.group(3), re.I)
                or rid.casefold() in seen or get(original, 'id', str).casefold() != rid.casefold()
                or original != row or get(wrapper, 'type', str) != kind
                or get(wrapper, 'scope', str).casefold() != scope.casefold()):
            raise Unavailable('malformed, duplicate, or foreign resource identity')
        seen.add(rid.casefold())
        provenance = get(row, '_provenance', dict)
        expected = 'LIST' if kind == 'ml_compute' else 'GET'
        if get(provenance, 'source_operation', str) != expected or get(provenance, 'read_only', bool) is not True:
            raise Unavailable('native read provenance unavailable')
    if get(item, 'id', str).casefold() not in seen or not any(row == item for row in rows):
        raise Unavailable('resource is not in complete scoped inventory')
    return rows


def _proof(item, key):
    evidence = get(item, 'sw29Evidence.' + key, dict)
    if get(evidence, 'status', str) != 'collected' or get(evidence, 'read_only', bool) is not True:
        raise Unavailable(key + ' evidence incomplete')
    if get(evidence, 'resource_id', str).casefold() != get(item, 'id', str).casefold():
        raise Unavailable(key + ' evidence foreign resource')
    return evidence


def _policy(index, name):
    policy = get(index, 'context.metadata.sw29.' + name, dict)
    if get(policy, 'status', str) != 'collected' or get(policy, 'read_only', bool) is not True:
        raise Unavailable(name + ' policy unavailable')
    if get(policy, 'scope', str).casefold() != get(index, 'context.scope', str).casefold():
        raise Unavailable(name + ' policy foreign scope')
    return policy


def _classification(item, index):
    policy = _policy(index, 'classification')
    assignments = get(policy, 'assignments', list)
    matches = [row for row in assignments if get(row, 'resource_id', str).casefold() == get(item, 'id', str).casefold()]
    if len(matches) != 1:
        raise Unavailable('authoritative classification missing or duplicated')
    label = get(matches[0], 'classification', str)
    if label not in ('sensitive', 'non_sensitive'):
        raise Unavailable('unrecognized ML sensitivity classification')
    return label


def _bool(evidence, name):
    return get(evidence, name, bool)


def _pg(item, index, field):
    _inventory(index, 'postgresql_single_server', item)
    if field == 'log_retention_days':
        coverage = get(item, '_coverage.configurations.status', str)
        if coverage not in ('collected', 'empty'):
            raise Unavailable('configuration pages incomplete')
        configs = get(item, 'configurations', list)
        if (coverage == 'empty') != (not configs):
            raise Unavailable('configuration coverage conflicts with page contents')
        matches = []
        for row in configs:
            rid = get(row, 'id', str)
            name = get(row, 'name', str)
            if rid.casefold() != (get(item, 'id', str) + '/configurations/' + name).casefold() or '/' in name:
                raise Unavailable('foreign configuration')
            if name.casefold() == field:
                matches.append(row)
        if len(matches) != 1:
            raise Unavailable('log_retention_days missing or duplicated')
        value = get(matches[0], 'properties.value', str)
        if not re.fullmatch(r'\d+', value):
            raise Unavailable('log_retention_days not an integer')
        return result(int(value) <= 3, value=int(value))
    value = get(item, 'properties.' + field, str)
    if value not in ('Enabled', 'Disabled'):
        raise Unavailable('unrecognized ' + field + ' enum')
    return result(value == 'Disabled', value=value)


def _ml_public(item, index):
    _inventory(index, 'ml_compute', item)
    if _classification(item, index) != 'non_sensitive':
        return 'NOT_APPLICABLE', {'reason': 'sensitive compute is outside this control'}
    enabled = get(item, 'properties.properties.enableNodePublicIp', bool)
    if not enabled:
        return 'NOT_APPLICABLE', {'reason': 'node public IP disabled'}
    proof = _proof(item, 'publicAccess')
    now = _instant(get(index, 'context.created_at', str))
    registry = get(proof, 'exception_registry_complete', bool)
    exceptions = get(proof, 'exceptions', list)
    valid = False
    for row in exceptions:
        if get(row, 'resource_id', str).casefold() != get(item, 'id', str).casefold():
            raise Unavailable('foreign public access exception')
        if get(row, 'approved', bool) and _instant(get(row, 'expires_at', str)) > now:
            valid = True
    if registry and not valid:
        return result(True, reason='no current approved exception')
    paths = get(proof, 'effective_ingress_paths', list)
    if get(proof, 'network_policy_complete', bool) and any(get(path, 'complies_with_approved_controls', bool) is False for path in paths):
        return result(True, reason='measured ingress path violates approved controls')
    if not registry or not valid or not get(proof, 'effective_paths_complete', bool) or not get(proof, 'network_policy_complete', bool):
        raise Unavailable('exception or effective ingress evidence incomplete')
    return result(False, effective_path_count=len(paths))


def _ml_root(item, index):
    _inventory(index, 'ml_compute', item)
    if _classification(item, index) != 'non_sensitive':
        return 'NOT_APPLICABLE', {'reason': 'sensitive compute is outside this control'}
    proof = _proof(item, 'rootAccess')
    enabled = _bool(proof, 'root_enabled')
    if not enabled and _bool(proof, 'managed_nodes_complete'):
        return result(False, reason='root disabled on all managed nodes')
    if not enabled:
        raise Unavailable('managed-node root state incomplete')
    if not _bool(proof, 'exception_registry_complete'):
        raise Unavailable('root exception registry incomplete')
    approvals = get(proof, 'exceptions', list)
    now = _instant(get(index, 'context.created_at', str))
    valid = any(get(row, 'resource_id', str).casefold() == get(item, 'id', str).casefold()
                and get(row, 'approved', bool) and get(row, 'necessary', bool)
                and _instant(get(row, 'expires_at', str)) > now for row in approvals)
    if not valid:
        return result(True, reason='root enabled without necessary current approval')
    if not _bool(proof, 'managed_nodes_complete'):
        raise Unavailable('managed-node root evidence incomplete')
    return result(False, reason='necessary root access covered by current instance approval')


def _ml_terminal(item, index):
    _inventory(index, 'ml_compute', item)
    if get(item, 'properties.computeType', str) != 'ComputeInstance':
        return 'NOT_APPLICABLE', {'reason': 'not an AML ComputeInstance'}
    if _classification(item, index) != 'non_sensitive':
        return 'NOT_APPLICABLE', {'reason': 'sensitive compute is outside this control'}
    proof = _proof(item, 'terminalAccess')
    if not _bool(proof, 'effective_access_complete'):
        raise Unavailable('effective terminal access incomplete')
    enabled = _bool(proof, 'terminal_enabled')
    if not enabled:
        return result(False, reason='effective terminal access disabled')
    if not _bool(proof, 'sessions_complete') or not _bool(proof, 'exception_registry_complete'):
        raise Unavailable('terminal sessions or exceptions incomplete')
    sessions = get(proof, 'sessions', list)
    approvals = get(proof, 'exceptions', list)
    if not sessions:
        # Enabled terminal access itself requires a scoped exception.
        if not any(get(a, 'resource_id', str).casefold() == get(item, 'id', str).casefold()
                   and get(a, 'approved', bool) and get(a, 'necessary', bool)
                   and _instant(get(a, 'expires_at', str)) > _instant(get(index, 'context.created_at', str)) for a in approvals):
            return result(True, reason='terminal enabled without current exception')
        return result(False, reason='enabled terminal access covered by necessary current exception')
    for session in sessions:
        principal = get(session, 'principal_id', str)
        when = _instant(get(session, 'started_at', str))
        if not any(get(a, 'resource_id', str).casefold() == get(item, 'id', str).casefold()
                   and get(a, 'principal_id', str) == principal and get(a, 'approved', bool)
                   and get(a, 'necessary', bool) and _instant(get(a, 'starts_at', str)) <= when
                   < _instant(get(a, 'expires_at', str)) for a in approvals):
            return result(True, reason='unauthorized terminal session', principal_id=principal)
    return result(False, session_count=len(sessions))


def _ml_network(item, index, sensitive):
    _inventory(index, 'ml_compute', item)
    label = _classification(item, index)
    if label != ('sensitive' if sensitive else 'non_sensitive'):
        return 'NOT_APPLICABLE', {'reason': 'compute outside classified scope'}
    subnet = get(item, 'properties.properties.subnet.id', str)
    if not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+/subnets/[^/]+', subnet, re.I):
        raise Unavailable('ML subnet identity malformed')
    proof = _proof(item, 'networkBaseline')
    if get(proof, 'subnet_id', str).casefold() != subnet.casefold():
        raise Unavailable('subnet evidence mismatches compute')
    policy = _policy(index, 'approvedNetworkBaseline')
    if sensitive:
        approved = get(policy, 'approved_sensitive_subnet_ids', list)
        if any(not isinstance(v, str) for v in approved):
            raise Unavailable('approved subnet list malformed')
        if subnet.casefold() not in {v.casefold() for v in approved} and _bool(proof, 'subnet_get_complete'):
            return result(True, reason='compute outside approved sensitive subnets')
    if not _bool(proof, 'subnet_get_complete'):
        raise Unavailable('subnet GET incomplete')
    nsg = proof.get('network_security_group_id')
    if nsg is None:
        return result(True, reason='complete subnet GET has no NSG')
    if not isinstance(nsg, str) or not nsg:
        raise Unavailable('malformed NSG association')
    if not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Network/networkSecurityGroups/[^/]+', nsg, re.I):
        raise Unavailable('malformed NSG ARM identity')
    controls = get(proof, 'effective_controls', list)
    if _bool(proof, 'baseline_complete'):
        if any(get(c, 'complies', bool) is False for c in controls):
            return result(True, reason='effective network control violates baseline')
        required = get(policy, 'required_control_names', list)
        if not required or any(not isinstance(v, str) for v in required):
            raise Unavailable('approved baseline controls missing')
        measured = {get(c, 'name', str) for c in controls}
        if not set(required) <= measured:
            raise Unavailable('effective baseline control missing')
        return result(False, control_count=len(controls))
    raise Unavailable('effective network baseline incomplete')


def _gateway(item, index):
    _inventory(index, 'application_gateway', item)
    return get(item, 'properties', dict)


def _children(props, name, parent, child_kind):
    rows = get(props, name, list)
    seen = set()
    for row in rows:
        rid = get(row, 'id', str)
        prefix = parent + '/' + child_kind + '/'
        if not rid.casefold().startswith(prefix.casefold()) or '/' in rid[len(prefix):] or not rid[len(prefix):] or rid.casefold() in seen:
            raise Unavailable('malformed or duplicate gateway ' + name)
        seen.add(rid.casefold())
    return rows


def _https(item, props):
    rid = get(item, 'id', str)
    listeners = _children(props, 'httpListeners', rid, 'httpListeners')
    result_rows = []
    for listener in listeners:
        protocol = get(listener, 'properties.protocol', str)
        if protocol not in ('Http', 'Https'):
            raise Unavailable('unrecognized listener protocol')
        if protocol == 'Https':
            result_rows.append(listener)
    return result_rows


def _gateway_cert(item, index):
    props = _gateway(item, index)
    listeners = _https(item, props)
    if not listeners:
        return 'NOT_APPLICABLE', {'reason': 'no HTTPS listener'}
    certificates = {get(row, 'id', str).casefold(): row for row in _children(props, 'sslCertificates', get(item, 'id', str), 'sslCertificates')}
    missing = []
    bound = []
    for listener in listeners:
        lid = get(listener, 'id', str)
        ref = get(listener, 'properties.sslCertificate.id', str) if 'sslCertificate' in get(listener, 'properties', dict) else None
        if ref is None:
            missing.append(lid)
            continue
        cert = certificates.get(ref.casefold())
        if cert is None:
            raise Unavailable('HTTPS certificate reference unresolved')
        uri = get(cert, 'properties.keyVaultSecretId', str) if 'keyVaultSecretId' in get(cert, 'properties', dict) else ''
        if not uri:
            missing.append(lid)
        elif not re.fullmatch(r'https://[A-Za-z0-9.-]+\.vault\.azure\.net/secrets/[^/]+(?:/[^/]+)?', uri):
            raise Unavailable('Key Vault secret URI malformed')
        else:
            bound.append(lid)
    if missing:
        return result(True, listeners_without_key_vault=missing)
    proof = _proof(item, 'certificateValidation')
    rows = get(proof, 'listeners', list)
    if len(rows) != len(bound):
        raise Unavailable('certificate validation listener coverage incomplete')
    seen = set()
    for row in rows:
        lid = get(row, 'listener_id', str)
        if lid.casefold() not in {v.casefold() for v in bound} or lid.casefold() in seen:
            raise Unavailable('foreign or duplicate validated listener')
        seen.add(lid.casefold())
        if not _bool(row, 'key_vault_accessible') or not _bool(row, 'certificate_valid') or not _bool(row, 'chain_trusted'):
            return result(True, reason='bound certificate invalid, untrusted, or inaccessible', listener_id=lid)
    return result(False, listener_count=len(bound))


def _gateway_tls(item, index):
    props = _gateway(item, index)
    listeners = _https(item, props)
    if not listeners:
        return 'NOT_APPLICABLE', {'reason': 'no HTTPS listener'}
    policy = _policy(index, 'approvedSslPolicy')
    min_version = get(policy, 'minimum_protocol', str)
    if min_version not in ('TLSv1_2', 'TLSv1_3'):
        raise Unavailable('approved TLS minimum unknown')
    approved_ciphers = get(policy, 'approved_cipher_suites', list)
    if not approved_ciphers or any(not isinstance(v, str) for v in approved_ciphers):
        raise Unavailable('approved cipher policy missing')
    profiles = {get(row, 'id', str).casefold(): row for row in _children(props, 'sslProfiles', get(item, 'id', str), 'sslProfiles')}
    weak = []
    for listener in listeners:
        config = get(listener, 'properties', dict)
        if 'sslProfile' in config:
            profile = profiles.get(get(config, 'sslProfile.id', str).casefold())
            if profile is None:
                raise Unavailable('listener SSL profile unresolved')
            effective = get(profile, 'properties.sslPolicy', dict)
        else:
            effective = get(props, 'sslPolicy', dict)
        policy_type = get(effective, 'policyType', str)
        if policy_type != 'Custom':
            if policy_type in ('Predefined', 'CustomV2'):
                weak.append(get(listener, 'id', str))
                continue
            raise Unavailable('unrecognized SSL policy type')
        version = get(effective, 'minProtocolVersion', str)
        ciphers = get(effective, 'cipherSuites', list)
        if version not in ('TLSv1_0', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3') or not ciphers or any(not isinstance(v, str) for v in ciphers):
            raise Unavailable('unresolved custom SSL policy')
        if ('TLSv1_0', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3').index(version) < ('TLSv1_0', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3').index(min_version) or not set(ciphers) <= set(approved_ciphers):
            weak.append(get(listener, 'id', str))
    if weak:
        return result(True, weak_listener_ids=weak)
    frontdoor = _proof(item, 'frontDoorTls')
    if not _bool(frontdoor, 'family_inventory_complete'):
        raise Unavailable('Front Door family inventory incomplete')
    domains = get(frontdoor, 'domains', list)
    for domain in domains:
        if not _bool(domain, 'effective_policy_resolved'):
            raise Unavailable('Front Door TLS policy unresolved')
        if not _bool(domain, 'approved_minimum_and_ciphers'):
            return result(True, reason='weaker Front Door TLS policy', domain_id=get(domain, 'id', str))
    return result(False, https_listener_count=len(listeners), front_door_domain_count=len(domains))


def _gateway_affinity(item, index):
    _gateway(item, index)
    proof = _proof(item, 'affinityProbes')
    if not _bool(proof, 'route_inventory_complete'):
        raise Unavailable('affinity route inventory incomplete')
    routes = get(proof, 'routes', list)
    applicable = [row for row in routes if _bool(row, 'affinity_enabled')]
    if not applicable:
        return 'NOT_APPLICABLE', {'reason': 'no affinity route'}
    uncertain = False
    for route in applicable:
        if not _bool(route, 'session_continuity_proven') or not _bool(route, 'idle_probe_complete'):
            uncertain = True
            continue
        idle = get(route, 'idle_seconds', int)
        if idle <= 1800:
            uncertain = True
            continue
        if _bool(route, 'same_session_accepted'):
            return result(True, route_id=get(route, 'route_id', str), idle_seconds=idle)
    if uncertain:
        raise Unavailable('affinity inactivity measurement incomplete')
    return result(False, route_count=len(applicable))


def _gateway_rate(item, index):
    _gateway(item, index)
    proof = _proof(item, 'rateLimit')
    if not _bool(proof, 'public_exposure_measured'):
        raise Unavailable('public gateway exposure unresolved')
    if not _bool(proof, 'public'):
        return 'NOT_APPLICABLE', {'reason': 'gateway not publicly reachable'}
    if not _bool(proof, 'effective_policy_complete') or not _bool(proof, 'rules_and_priority_complete'):
        raise Unavailable('effective WAF policy or priority incomplete')
    rules = get(proof, 'effective_rules', list)
    qualifying = []
    for rule in rules:
        state = rule.get('state', 'Enabled')
        if state not in ('Enabled', 'Disabled'):
            raise Unavailable('unrecognized custom rule state')
        if (state == 'Enabled' and get(rule, 'policy_mode', str) == 'Prevention'
                and get(rule, 'rule_type', str) == 'RateLimitRule'
                and get(rule, 'action', str) == 'Block'
                and get(rule, 'duration', str) == 'FiveMins'
                and get(rule, 'threshold', int) <= 2000
                and get(rule, 'group_by', str) == 'ClientAddr'
                and _bool(rule, 'effective_conditions_verified')
                and _bool(rule, 'not_shadowed')):
            qualifying.append(rule)
    if not qualifying:
        return result(True, reason='no effective qualifying client rate-limit rule')
    if not _bool(proof, 'runtime_window_complete'):
        raise Unavailable('sliding-window runtime evidence incomplete')
    if not _bool(proof, 'sliding_five_minute_limit_enforced') or get(proof, 'measured_block_seconds', int) < 60:
        return result(True, reason='measured throttling inadequate')
    return result(False, qualifying_rule_count=len(qualifying))


def _gateway_header(item, index):
    _gateway(item, index)
    proof = _proof(item, 'serverHeader')
    if not _bool(proof, 'path_inventory_complete'):
        raise Unavailable('gateway response paths incomplete')
    paths = get(proof, 'paths', list)
    if not paths:
        return 'NOT_APPLICABLE', {'reason': 'no response path'}
    uncertain = False
    for path in paths:
        pid = get(path, 'path_id', str)
        if not _bool(path, 'association_and_precedence_complete'):
            uncertain = True
            continue
        if not _bool(path, 'unconditional_rewrite_to_lb'):
            return result(True, reason='response path lacks effective Server rewrite', path_id=pid)
        if not _bool(path, 'runtime_sample_complete'):
            uncertain = True
            continue
        if get(path, 'sampled_server_header', str) != 'lb':
            return result(True, reason='sampled Server header differs from lb', path_id=pid)
    if uncertain:
        raise Unavailable('gateway header paths or samples incomplete')
    return result(False, path_count=len(paths))


def _gateway_throttle(item, index):
    _gateway(item, index)
    proof = _proof(item, 'throttleLogs')
    if not _bool(proof, 'logging_enabled'):
        if _bool(proof, 'diagnostic_settings_complete'):
            return result(True, reason='gateway access logging disabled')
        raise Unavailable('gateway logging state incomplete')
    if not _bool(proof, 'diagnostic_settings_complete') or not _bool(proof, 'invocation_timeline_complete') or not _bool(proof, 'log_query_complete'):
        raise Unavailable('throttle timeline or log query incomplete')
    invocations = get(proof, 'invocations', list)
    if not invocations:
        raise Unavailable('no in-window throttling invocation to assess')
    now = _instant(get(index, 'context.created_at', str))
    for invocation in invocations:
        when = _instant(get(invocation, 'invoked_at', str))
        if when > now - timedelta(minutes=5):
            raise Unavailable('five-minute log deadline not yet observable')
        event = invocation.get('correlated_log_at')
        if event is None:
            return result(True, reason='correlated access log absent from complete query')
        delay = (_instant(event) - when).total_seconds()
        if delay < 0:
            raise Unavailable('log timestamp precedes invocation')
        if delay > 300:
            return result(True, reason='correlated access log late', delay_seconds=delay)
    return result(False, invocation_count=len(invocations))


def _gateway_renew(item, index):
    _gateway(item, index)
    proof = _proof(item, 'certificateRenewal')
    if not _bool(proof, 'bindings_and_versions_complete') or not _bool(proof, 'history_complete'):
        raise Unavailable('certificate bindings, versions, or history incomplete')
    entries = get(proof, 'renewals', list)
    if not entries:
        return 'NOT_APPLICABLE', {'reason': 'no bound certificate entered renewal window'}
    now = _instant(get(index, 'context.created_at', str))
    uncertain = False
    for row in entries:
        trigger = _instant(get(row, 'trigger_at', str))
        expiry = _instant(get(row, 'expires_at', str))
        if not 0 <= (expiry - trigger).total_seconds() <= 30 * 86400:
            raise Unavailable('renewal trigger outside 30-day expiry window')
        deadline = trigger + timedelta(hours=24)
        if now < deadline:
            uncertain = True
            continue
        if not _bool(row, 'version_fingerprint_join_complete') or not _bool(row, 'listener_observations_complete'):
            uncertain = True
            continue
        issued = row.get('new_valid_version_issued_at')
        served = row.get('new_version_served_at')
        if issued is None or served is None:
            return result(True, reason='renewal deadline passed without serving valid new version')
        if _instant(issued) > _instant(served) or _instant(served) > deadline:
            return result(True, reason='new version served after renewal deadline')
    if uncertain:
        raise Unavailable('renewal deployment deadline or observations unresolved')
    return result(False, renewal_count=len(entries))

_RULES = {
    'azure.cis.legacy_infrastructure_double_encryption_postgresql_single_server': lambda i, x: _pg(i, x, 'infrastructureEncryption'),
    'azure.cis.postgresql_single_log_retention_days': lambda i, x: _pg(i, x, 'log_retention_days'),
    'azure.cis.postgresql_single_ssl_enforcement': lambda i, x: _pg(i, x, 'sslEnforcement'),
    'azure.other.ml_public_access_exception': _ml_public,
    'azure.other.ml_root_exception': _ml_root,
    'azure.other.ml_terminal_exception': _ml_terminal,
    'azure.other.ml_sensitive_subnet_allowlist': lambda i, x: _ml_network(i, x, True),
    'azure.other.ml_subnet_baseline': lambda i, x: _ml_network(i, x, False),
    'azure.other.gateway_affinity_cookie_timeout': _gateway_affinity,
    'azure.other.gateway_client_rate_limit': _gateway_rate,
    'azure.other.gateway_server_header_rewrite': _gateway_header,
    'azure.other.gateway_throttle_log_alert': _gateway_throttle,
    'azure.other.lb_certificate_auto_renew': _gateway_renew,
    'azure_application_gateway_1_2_5_8_33a9d21': _gateway_tls,
    'azure_application_gateway_app_client_certificates_on_fcca0b8': _gateway_cert,
}

for _id, _spec in SPECS.items():
    # The central registry currently recognizes a narrower set of categories
    # than the signed ledger. Preserve signed category on the frozen Check.
    _category = _spec['category']
    _registered_category = _category if _category in ('hardening', 'network', 'exposure', 'least_privilege', 'iam_graph') else 'hardening'
    @register(_id, _spec['provider'], _registered_category, _spec['resource_kind'],
              _spec['title'], _spec['severity'], 'CM-6', _spec['remediation_hint'],
              dependencies=[_spec['resource_kind']])
    def _evaluate(item, index, _check_id=_id):
        return _RULES[_check_id](item, index)
    if _category != _registered_category:
        object.__setattr__(CHECKS[-1], 'category', _category)
