"""Reviewed, exact-check Kubernetes observations with short security explanations.

The JSON records the interpretation of each registered evaluator contract. Native
facts still come from validated predicate witnesses, not a finding title/status.
"""
from functools import lru_cache
import json
from pathlib import Path

from .k8s_observed_configuration import evidence_summary as native_observation


@lru_cache(maxsize=1)
def review_rows():
    return json.loads(Path(__file__).with_suffix('.json').read_text())


@lru_cache(maxsize=1)
def current_review_rows():
    rows = json.loads(Path(__file__).with_name('k8s_evidence_explanations_current_20261023.json').read_text())
    if set(rows) & set(review_rows()):
        raise ValueError('Kubernetes current explanation duplicates a historical review')
    return rows


def all_review_rows():
    return {**review_rows(), **current_review_rows()}


def _text(value, maximum=200):
    return value if isinstance(value, str) and 0 < len(value) <= maximum and all(ord(c) >= 32 for c in value) else None


def reviewed_explanation(check_id, observation, status=None):
    """Also used by clients formatting older reports without server summaries."""
    if not isinstance(check_id, str):
        return None
    row = review_rows().get(check_id) or current_review_rows().get(check_id)
    if row is None or not _text(observation, 2000):
        return None
    if check_id == 'k8s.review.selected_metadata.secret_indicators' and any(
            text in observation for text in ('selected object labels and annotations', 'selected object labels or annotations')):
        return observation  # The native observation already names this exact scope.
    purpose = row['purpose']
    if purpose in observation:
        return observation
    if status in ('UNKNOWN', 'DENIED', 'ERROR'):
        # The observation already explains why the evidence is unavailable.
        return observation.rstrip() + ' ' + purpose
    return ' '.join(part for part in (observation.rstrip(), purpose, row.get('limit')) if part)


def _rule_text(evidence, field):
    rules = evidence.get(field)
    if not isinstance(rules, list) or not rules:
        return None
    rule = rules[0]
    if not isinstance(rule, dict):
        return None
    values = [rule.get(key) for key in ('apiGroups', 'resources', 'verbs')]
    if any(not isinstance(v, list) or not v or any(not isinstance(x, str) or len(x) > 100 or any(ord(ch) < 32 for ch in x) for x in v) for v in values):
        return None
    _, resources, verbs = values
    if len(resources) > 4 or len(verbs) > 4:
        return 'The role declares a matching sensitive RBAC rule; the full resource and action lists are in the evidence.'
    return 'The role declares ' + ', '.join('“' + x + '”' for x in verbs) + ' access to ' + ', '.join('“' + x + '”' for x in resources) + '.'


def _duration_words(value):
    """Translate captured Go-style time units without interpreting missing values."""
    import re
    from decimal import Decimal
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|ms|h|m|s))+|0', value):
        return None
    labels = {'h': 'hour', 'm': 'minute', 's': 'second', 'ms': 'millisecond', 'us': 'microsecond', 'µs': 'microsecond', 'ns': 'nanosecond'}
    parts = []
    for number, unit in re.findall(r'([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|h|m|s)', value):
        amount = Decimal(number)
        if amount:
            parts.append(number + ' ' + labels[unit] + ('' if amount == 1 else 's'))
    return ' and '.join(parts) if parts else 'zero seconds'


def _permission_sentence(mode):
    try:
        value = int(mode, 8)
    except (TypeError, ValueError):
        return None
    if not 0 <= value <= 0o7777:
        return None
    basic = value & 0o777
    explanations = {
        0o000: 'sets no read, write or execute permission bits',
        0o400: 'allows only the owner to read',
        0o600: 'allows only the owner to read and write',
        0o644: 'allows everyone to read and only the owner to write',
        0o700: 'gives only the owner read, write and execute permissions',
        0o755: 'allows everyone to read and execute, and only the owner to write',
        0o777: 'allows everyone to read, write and execute',
    }
    if not value & 0o7000 and basic in explanations:
        return f'The supplied file mode {value:04o} ' + explanations[basic] + '.'
    special = [label for bit, label in ((0o4000, 'set-user-ID'), (0o2000, 'set-group-ID'), (0o1000, 'sticky')) if value & bit]
    if special:
        return f'The supplied mode {value:04o} sets ' + ' and '.join(special) + ' permission bits.'
    def rights(bits):
        selected = [label for bit, label in ((4, 'read'), (2, 'write'), (1, 'execute')) if bits & bit]
        return ' and '.join(selected) if selected else 'no permissions'
    return f'The supplied mode {value:04o} gives '+rights((value >> 6) & 7)+' to the owner, '+rights((value >> 3) & 7)+' to the group, and '+rights(value & 7)+' to others.'


def _component_sentence(finding, row, validated):
    binding = row.get('binding', {})
    fields = binding.get('fields', [])
    if not fields:
        return validated
    field = fields[0]
    for observation in finding['evidence'].get('observations', []):
        if not isinstance(observation, dict):
            continue
        name, component, settings = observation.get('container'), observation.get('component'), observation.get('settings')
        if not _text(name) or not _text(component) or not isinstance(settings, dict):
            continue
        if not validated.startswith(f'Container “{name}” declares {component} '):
            continue
        value = settings.get(field)
        prefix = f'Container “{name}” declares {component} '
        if field == 'authorization-mode' and isinstance(value, str):
            modes = set(value.split(','))
            if 'AlwaysAllow' in modes:
                return prefix + 'with authorization checks bypassed by the allow-all mode.'
            descriptions = {'Node': 'node authorization', 'RBAC': 'role-based authorization', 'Webhook': 'webhook authorization'}
            if modes and modes <= descriptions.keys():
                return prefix + 'with ' + ' and '.join(descriptions[m] for m in sorted(modes)) + '.'
        if field == 'enable-admission-plugins' and isinstance(value, str):
            expected = binding.get('expected')
            expected = [expected] if isinstance(expected, str) else expected
            if isinstance(expected, (list, tuple)):
                declared = [plugin for plugin in expected if plugin in value.split(',')]
                if declared:
                    return prefix + 'with ' + ' or '.join(declared) + ' admission configured.'
                return prefix + 'without ' + ' or '.join(expected) + ' in its admission configuration.'
        if field == 'feature-gates' and isinstance(value, str):
            gates = value.split(',')
            if 'RotateKubeletServerCertificate=true' in gates:
                return prefix + 'with kubelet serving-certificate rotation enabled.'
            if 'RotateKubeletServerCertificate=false' in gates:
                return prefix + 'with kubelet serving-certificate rotation disabled.'
            return prefix + 'without an enabled kubelet serving-certificate rotation declaration.'
        if field == 'tls-cipher-suites' and isinstance(value, str):
            if not value:
                return prefix + 'without a TLS cipher-suite selection.'
            return prefix + ('using only reviewed TLS cipher suites.' if finding['status'] == 'PASS' else 'using a TLS cipher suite outside the reviewed list.')
        if field == 'streaming-connection-idle-timeout':
            duration = _duration_words(value)
            if duration:
                return prefix + ('without an idle timeout for streaming connections.' if duration == 'zero seconds' else f'with a streaming idle timeout of {duration}.')
    return validated


def _scalar_sentence(finding, row):
    e, cid = finding['evidence'], finding['check_id']
    field = row['field']
    if field not in e:
        return None
    value = e[field]
    if cid == 'k8s.ports.configuration.kubelet_authorization_mode':
        meanings = {'Webhook': 'delegates permission checks to a webhook', 'AlwaysAllow': 'allows requests without authorization checks'}
        if isinstance(value, str) and value in meanings:
            return 'The supplied kubelet configuration ' + meanings[value] + '.'
        return f'The supplied kubelet configuration declares authorization mode “{value}”.' if _text(value) else None
    boolean_meanings = {
        'k8s.ports.configuration.kubelet_disable_anonymous_auth': ('allows unauthenticated requests', 'disables anonymous authentication'),
        'k8s.ports.configuration.kubelet_manage_iptables': ('manages iptables utility chains', 'does not manage iptables utility chains'),
        'k8s.ports.configuration.kubelet_rotate_certificates': ('enables client-certificate rotation', 'disables client-certificate rotation'),
        'k8s.cis.the_seccomp_default_parameter_is_set_to_true': ('enables default seccomp filtering', 'disables default seccomp filtering'),
        'k8s.cis.kubelet_rotate_kubelet_server_certificate_true': ('enables serving-certificate rotation', 'disables serving-certificate rotation'),
    }
    if cid in boolean_meanings:
        if type(value) is not bool:
            return None
        return 'The supplied kubelet configuration ' + boolean_meanings[cid][0 if value else 1] + '.'
    if cid == 'k8s.ports.configuration.kubelet_disable_read_only_port' and type(value) is int and 0 <= value <= 65535:
        return 'The supplied kubelet configuration disables its unauthenticated read-only listener.' if value == 0 else f'The supplied kubelet configuration declares an unauthenticated read-only listener on port {value}.'
    if cid == 'k8s.claude.configuration.kubelet_client_ca_file':
        if value is None:
            return 'The supplied kubelet configuration declares no client certificate-authority file.'
        if _text(value):
            return f'The supplied kubelet configuration references client certificate trust file “{value}”.'
    if cid == 'k8s.claude.configuration.kubelet_streaming_timeout':
        duration = _duration_words(value)
        if duration:
            return 'The supplied kubelet configuration sets no idle timeout for streaming connections.' if duration == 'zero seconds' else f'The supplied kubelet configuration sets a streaming idle timeout of {duration}.'
    if cid == 'k8s.cis.a_limit_is_set_on_pod_pids' and type(value) is int:
        if value <= 0:
            return 'The supplied kubelet configuration sets no positive per-Pod process limit.'
        return f'The supplied kubelet configuration declares a per-Pod process limit of {value}.'
    if cid == 'k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost' and _text(value):
        return f'The kube-proxy declaration binds metrics to “{value}”.'
    return None


def _precise_native(finding, row):
    e, status = finding['evidence'], finding['status']
    binding = row.get('binding')
    if not isinstance(binding, dict):
        return None
    predicate = binding.get('predicate')
    if predicate == 'backend_https':
        if 'declared_backend_protocol' not in e:
            return None
        value, services = e.get('declared_backend_protocol'), e.get('resolved_backend_services')
        if not isinstance(services, list) or not services or any(not _text(v) for v in services):
            return None
        if value not in (None, 'HTTP', 'HTTPS', 'GRPC', 'GRPCS', 'FCGI', 'AUTO_HTTP'):
            return None
        if (value in ('HTTPS', 'GRPCS')) != (status == 'PASS'):
            return None
        return 'The Ingress declares backend protocol “' + value + '” for resolved Services.' if value else 'The Ingress has no backend-protocol annotation for resolved Services.'
    if predicate == 'pod_runtime_default_seccomp' and e.get('declared_pod_profile', object()) is None and status == 'FAIL':
        return 'The PodSpec declares no Pod-level seccomp profile.'
    if predicate == 'wildcard' and status == 'FAIL':
        rules = e.get('declared_wildcards')
        if not isinstance(rules, list) or not rules:
            return None
        labels = {'verbs': 'actions', 'resources': 'resources', 'apiGroups': 'API groups'}
        for rule in rules:
            if not isinstance(rule, dict) or rule.get('field') not in labels:
                continue
            values = rule.get('values')
            if not isinstance(values, list) or any(not _text(v) for v in values):
                continue
            for value in values:
                if '*' in value:
                    return f'The role declares wildcard “{value}” in its {labels[rule["field"]]}.'
        return None
    if status == 'FAIL':
        field = {'sensitive_rbac': 'declared_sensitive_rules', 'csr_review': 'declared_csr_approval_rules'}.get(predicate)
        if predicate in ('no_pod_create', 'no_secret_read', 'no_bind', 'impersonation', 'no_pod_interactive_access', 'no_workload_controller_write', 'no_service_status_write', 'no_human_csr_approval', 'no_human_node_proxy', 'no_human_pv_create', 'no_human_serviceaccount_token_create', 'no_human_webhook_config_write'):
            field = 'matching_rules'
        if field:
            return _rule_text(e, field)
        if predicate in ('k8s_wildcards', 'no_wildcard_resources_or_verbs'):
            return _rule_text(e, 'wildcard_rules')
        if predicate in ('k8s_subjects', 'default_subject', 'anonymous_binding'):
            field = {'k8s_subjects': 'broad_subjects', 'default_subject': 'default_serviceaccount_subjects', 'anonymous_binding': 'anonymous_subjects'}[predicate]
            subjects = e.get(field)
            if isinstance(subjects, list) and subjects and isinstance(subjects[0], dict):
                subject = subjects[0]
                if _text(subject.get('kind')) and _text(subject.get('name')):
                    return f'The binding names {subject["kind"]} “{subject["name"]}” as a role subject.'
        if predicate == 'no_literal_secret_env':
            values = e.get('literal_credential_env')
            if isinstance(values, list) and values and isinstance(values[0], dict):
                container, env = values[0].get('container'), values[0].get('env')
                if _text(container) and _text(env):
                    return f'Container “{container}” declares a nonempty literal in credential-like variable “{env}”.'
    observed = native_observation(finding)
    if observed and row.get('binding', {}).get('component'):
        observed = _component_sentence(finding, row, observed)
    if observed and predicate in ('plugin_deny_service_external_ips', 'plugin_event_rate_limit'):
        plugin = 'DenyServiceExternalIPs' if predicate == 'plugin_deny_service_external_ips' else 'EventRateLimit'
        return 'The API-server declaration ' + ('includes ' if status == 'PASS' else 'does not include ') + plugin + ' admission.'
    if observed and predicate == 'network_empty_rule':
        rules = e.get('unrestricted_rule_indexes')
        direction = e.get('direction')
        if isinstance(rules, list) and direction in ('Ingress', 'Egress'):
            return f'The policy declares {len(rules)} unrestricted {direction.lower()} '+('rule.' if len(rules) == 1 else 'rules.')
    if observed and predicate == 'declared_nonroot' and status == 'FAIL':
        return observed.replace('does not explicitly declare runAsNonRoot=true', 'does not explicitly require a non-root user')
    if observed and predicate == 'security_services_hardening':
        return 'The legacy Pod security policy requires configured SELinux labels.' if e.get('selinux_rule') == 'MustRunAs' else 'The legacy Pod security policy allows any SELinux label.'
    if observed and predicate == 'default_seccomp_profile':
        profile = e.get('default_profile')
        if profile in ('runtime/default', 'docker/default'):
            return 'The legacy Pod security policy selects the runtime’s default system-call filter.'
    if observed and status == 'PASS':
        if predicate == 'capabilities_dropped':
            return 'No assessed capabilities object adds capabilities or declares an empty drop list.'
        if predicate == 'no_root_user':
            return 'No evaluated regular container explicitly declares UID zero.'
        if predicate == 'network_default_allow' and e.get('direction') == 'Egress':
            return 'No assessed egress rule declares an unrestricted destination peer.'
    if observed and status == 'FAIL' and predicate == 'hostpath':
        paths = e.get('host_path_volumes')
        if isinstance(paths, list) and paths and isinstance(paths[0], dict) and _text(paths[0].get('path')):
            return f'The PodSpec declares hostPath mount “{paths[0]["path"]}”.'
    if observed:
        if predicate in ('always_pull', 'content_digest_or_always_pull') and status == 'PASS':
            return 'Evaluated images use an accepted SHA256 digest or the Always image-pull policy.'
        if predicate == 'no_host_ports':
            return 'An evaluated container declares a hostPort field.' if status == 'FAIL' else 'No evaluated container declares a hostPort field.'
    return observed


def _external_observation(finding, row):
    e, status = finding['evidence'], finding['status']
    fmt = row.get('format')
    if fmt == 'file':
        path = _text(e.get('path') or e.get('selector'))
        if not path:
            return None
        if _text(e.get('mode')):
            return _permission_sentence(e['mode'])
        if type(e.get('uid')) is int and type(e.get('gid')) is int:
            return f'The supplied metadata names the root user and group as owners of “{path}”.' if e['uid'] == e['gid'] == 0 else f'The supplied metadata names user ID {e["uid"]} and group ID {e["gid"]} as owners of “{path}”.'
        failures = e.get('failing_files')
        if status == 'FAIL' and isinstance(failures, list) and failures and isinstance(failures[0], dict):
            f = failures[0]
            if _text(f.get('path')):
                if _text(f.get('mode_octal')):
                    return _permission_sentence(f['mode_octal'])
                if type(f.get('uid')) is int and type(f.get('gid')) is int:
                    return f'The supplied metadata names user ID {f["uid"]} and group ID {f["gid"]} as owners of “{f["path"]}”.'
        count = e.get('assessed_file_count')
        if status == 'PASS' and type(count) is int and count > 0:
            return f'The supplied metadata meets the required {row["file_requirement"]} for “{path}”.'
        return None
    if fmt == 'scalar':
        return _scalar_sentence(finding, row)
    if fmt == 'list':
        values = e.get(row['field'])
        if not isinstance(values, list):
            return None
        if row['field'] == 'weak_ciphers' and not values:
            return 'The supplied evidence lists no unapproved cipher names; it does not record whether the configured cipher list is empty.'
        if bool(values) != (status == row.get('nonempty_status', 'FAIL')):
            return None
        return row['present'] if values else row['empty']
    if fmt == 'namespace_policy_count':
        count, namespace = e.get('network_policy_count'), e.get('namespace')
        if type(count) is int and count >= 0 and _text(namespace):
            return f'Namespace “{namespace}” has {count} recorded NetworkPolicy declarations.'
    if fmt == 'tls_files':
        if e.get('server_tls_bootstrap') is True:
            return 'Supplied kubelet configuration enables serving-certificate bootstrap.'
        declared = e.get('declared')
        if isinstance(declared, list) and declared and all(x in ('tlsCertFile', 'tlsPrivateKeyFile') for x in declared):
            return 'Supplied kubelet configuration declares ' + ('a TLS certificate and private key.' if len(set(declared)) == 2 else 'only a TLS certificate or private key, rather than both.')
    if fmt == 'namespace':
        namespace = _text(e.get('namespace'))
        if namespace:
            return f'The resource is declared in namespace “{namespace}”.'
    if fmt == 'service_type':
        observed, required = e.get('observed_type'), e.get('required_type')
        if observed not in ('LoadBalancer', 'NodePort', 'ClusterIP', 'ExternalName'):
            return None
        suffix = f'; owner policy requires {required}' if required in ('LoadBalancer', 'NodePort', 'ClusterIP', 'ExternalName') else ''
        return f'The Service declares type {observed}{suffix}.'
    if fmt == 'service_selection':
        assessed, wrong = e.get('assessed_count'), e.get('wrong_type_count')
        if type(assessed) is int and assessed > 0 and type(wrong) is int and wrong >= 0:
            return f'{wrong} of {assessed} assessed owner-selected Services declare a type other than LoadBalancer.'
    if fmt == 'binding':
        if _text(e.get('binding_id')):
            return 'The required response-team RBAC binding is declared.'
        if e.get('semantics') == 'required declared binding absent':
            return 'The required response-team RBAC binding is absent from the assessed inventory.'
    if fmt == 'version':
        observed, oldest = _text(e.get('observed')), _text(e.get('oldest'))
        if observed and oldest:
            return f'The cluster reports Kubernetes {observed}; the owner-supplied support floor is {oldest}.'
    if fmt == 'timeout':
        seconds, maximum = e.get('seconds'), e.get('approved_max_seconds')
        if type(seconds) in (int, float) and type(maximum) in (int, float):
            return f'The API request timeout is {seconds:g} seconds; the approved maximum is {maximum:g} seconds.'
    if fmt == 'event_rate':
        observed, required = e.get('observed'), e.get('required')
        if type(observed) in (int, float) and type(required) in (int, float):
            return f'Supplied kubelet configuration allows {observed:g} '+('event' if observed == 1 else 'events')+f' per second; the approved minimum is {required:g}.'
    if fmt == 'image_policy':
        if isinstance(e.get('approved_images'), list) and e['approved_images'] and status == 'PASS':
            return 'A recognized Deny admission binding declares the owner-approved image restriction.'
        if e.get('reason') == 'no Deny binding enforcing approved images on Pod CREATE and UPDATE' and status == 'FAIL':
            return 'No qualifying Deny binding enforces approved images on Pod creation and updates.'
    if fmt == 'policy_intent':
        if _text(e.get('policy')):
            if e.get('semantics') == 'definite isolation or allow-rule presence deviation':
                return 'The NetworkPolicy declaration differs from its owner-approved isolation or allow-rule requirement.'
            if e.get('semantics') == 'exact approved declaration and attested CNI enforcement':
                return 'The NetworkPolicy matches its owner-approved declaration and supplied network-plugin attestation.'
    if fmt == 'cluster_admin':
        subjects = e.get('subjects')
        if isinstance(subjects, list) and subjects and isinstance(subjects[0], dict):
            kind, name = subjects[0].get('kind'), subjects[0].get('name')
            if _text(kind) and _text(name):
                return f'The cluster-admin binding names {kind} “{name}” as a subject.'
    if fmt == 'image_provenance':
        if _text(e.get('admission_config_path')) and _text(e.get('webhook_kubeconfig_path')):
            return 'The verified admission-file declaration configures ImagePolicyWebhook with a webhook client configuration.'
        messages = {
            'ImagePolicyWebhook explicitly disabled': 'The API-server flags explicitly disable the ImagePolicyWebhook admission plugin.',
            'ImagePolicyWebhook disabled in explicit flags': 'The API-server flags do not enable the ImagePolicyWebhook admission plugin.',
            'admission control config path invalid': 'The declared admission configuration path is invalid.',
            'admission control config path is not absolute and normalized': 'The admission configuration path is not absolute and normalized.',
            'ImagePolicyWebhook plugin configuration absent': 'The verified admission configuration has no ImagePolicyWebhook plugin entry.',
            'ImagePolicyWebhook kubeConfigFile path invalid': 'The image-policy webhook client configuration path is invalid.',
        }
        reason = e.get('reason')
        return messages.get(reason) if isinstance(reason, str) else None
    if fmt == 'clock':
        bad, tolerance = e.get('out_of_tolerance_nodes'), e.get('approved_clock_skew_seconds')
        if isinstance(bad, list) and all(_text(name) for name in bad) and type(tolerance) in (int, float) and tolerance >= 0:
            return f'{len(bad)} assessed nodes exceed the owner-approved clock-skew limit of {tolerance:g} seconds.'
    if fmt == 'traffic_policy':
        observed, required = e.get('observed'), e.get('required')
        if observed in ('Cluster', 'Local') and required in ('Cluster', 'Local'):
            return f'The LoadBalancer Service declares external traffic policy {observed}; the owner requires {required}.'
    if fmt == 'node_policy':
        values = e.get('observed')
        if isinstance(values, dict) and values and all(_text(k) and _text(v) for k, v in values.items()):
            node, value = next(iter(values.items()))
            return f'For node “{node}”, the supplied Windows policy '+('declares a block-all IP restriction.' if value == 'Any' else f'sets its IP restriction to “{value}”.')
    return None


def _current_text(value):
    return isinstance(value, str) and bool(value) and len(value) <= 300 and all(ord(ch) >= 32 for ch in value)


def _current_list(value):
    return isinstance(value, list) and len(value) <= 1000 and all(isinstance(row, dict) for row in value)


def _current_native_observation(check_id, status, evidence):
    """Interpret only typed fields and fixed phrases emitted by the 15 reviewed predicates."""
    row = current_review_rows()[check_id]
    kind = row['kind']
    if kind == 'consumers':
        consumers = evidence.get('consumers')
        account = 'serviceaccount_' in check_id
        expected = (('recorded identity consumer exists', 'no recorded workload, RBAC, token or cloud-identity consumer')
                    if account else ('recorded RBAC consumer exists', 'no recorded binding or aggregation consumes this role'))
        if (not _current_text(evidence.get('resource_name')) or not _current_list(consumers)
                or any(not _current_text(consumer.get('kind')) or not (
                    _current_text(consumer.get('name')) or
                    consumer.get('kind') == 'workload_identity_association' and _current_text(consumer.get('annotation')))
                    for consumer in consumers)
                or evidence.get('reason') != expected[0 if status == 'PASS' else 1]
                or (status == 'PASS') != bool(consumers)):
            return None
        subject = ('ServiceAccount' if 'serviceaccount_' in check_id else
                   'ClusterRole' if 'clusterrole_' in check_id else 'Role')
        return (f'The captured {subject} has {len(consumers)} declared consumer ' + ('reference.' if len(consumers) == 1 else 'references.')
                if consumers else f'The captured {subject} has no declared consumer in the complete native inventory.')
    if kind == 'subjects':
        count = evidence.get('subject_count')
        missing, external = evidence.get('missing_service_accounts'), evidence.get('external_subjects')
        if (type(count) is not int or count < 0 or count > 1000
                or not isinstance(missing, list) or not isinstance(external, list)
                or any(not _current_text(value) for value in missing + external)
                or len(missing) + len(external) > count):
            return None
        if status == 'FAIL' and (count == 0 or missing) and evidence.get('reason') in (
                'binding has no subjects', 'binding names a missing ServiceAccount'):
            return ('The captured binding names no subjects.' if count == 0 else
                    f'The captured binding names {len(missing)} ServiceAccount ' + ('subject' if len(missing) == 1 else 'subjects') + ' missing from complete native inventory.')
        if status == 'PASS' and count > 0 and not missing and not external and evidence.get('reason') == 'all ServiceAccount subjects exist in the captured scope':
            return f'All {count} captured ServiceAccount subjects resolve in the native inventory.'
        return None
    if kind == 'token':
        if (evidence.get('threshold_days') != 90 or evidence.get('timestamp_precision') != 'UTC calendar day'
                or not _current_text(evidence.get('resource_name'))
                or not _current_text(evidence.get('last_used_date'))
                or not _current_text(evidence.get('service_account'))):
            return None
        days = evidence.get('days_since_last_successful_use')
        if type(days) is not int or days < 0:
            return None
        if status == 'PASS' and days <= 90 and evidence.get('reason') == 'successful use is within the inactivity threshold':
            return f'The tracked legacy token has a recorded last-use day within {days} days of observation.'
        if status == 'FAIL' and days > 90 and evidence.get('reason') == 'no successful use within a complete inactivity observation interval':
            return f'The tracked legacy token’s last recorded use was {days} days before observation.'
        return None
    summary = evidence.get('summary')
    if kind in ('reference', 'ingress', 'policy', 'service'):
        if (not isinstance(summary, str) or len(summary) > 700
                or '\nThis is a current API declaration, not observed traffic.\n' not in summary):
            return None
        fact = summary.split('\n', 1)[0]
        if kind == 'reference':
            if not _current_text(evidence.get('service_name')):
                return None
            if status == 'PASS' and ('owner matches the current same-namespace Service UID.' in fact
                    or 'names current same-namespace Service ' in fact):
                return 'The captured endpoint reference resolves to a current same-namespace Service.'
            if status == 'FAIL' and ('owner names an absent same-namespace Service.' in fact
                    or 'names absent same-namespace Service ' in fact):
                return 'The captured endpoint reference names a Service absent from the complete same-namespace inventory.'
        if kind == 'ingress':
            key = 'service_backends' if status == 'PASS' else 'missing_services'
            names = evidence.get(key)
            if (isinstance(names, list) and names and all(_current_text(name) for name in names)
                    and ((status == 'PASS' and 'every native Service backend resolves in this namespace.' in fact)
                         or (status == 'FAIL' and 'Ingress references missing same-namespace Service(s): ' in fact))):
                return (f'All {len(names)} declared Ingress Service backends resolve in the current namespace.' if status == 'PASS' else
                        f'{len(names)} declared Ingress Service ' + ('backend is' if len(names) == 1 else 'backends are') + ' absent from the complete same-namespace inventory.')
        if kind == 'policy':
            pods = evidence.get('selected_pods')
            if status == 'PASS' and isinstance(pods, list) and pods and all(_current_text(name) for name in pods) and 'NetworkPolicy selects ' in fact:
                return f'The NetworkPolicy selector matches at least {len(pods)} captured ' + ('Pod' if len(pods) == 1 else 'Pods') + ' in its namespace.'
            if status == 'FAIL' and 'NetworkPolicy selects no current Pods in its namespace.' in fact:
                return 'The NetworkPolicy selector matches no Pod in the complete current inventory.'
        if kind == 'service':
            pods, slices = evidence.get('selected_pods'), evidence.get('endpoint_slices')
            if status == 'PASS' and isinstance(pods, list) and pods and all(_current_text(name) for name in pods) and 'Service selector matches ' in fact:
                return f'The Service selector matches at least {len(pods)} captured ' + ('Pod.' if len(pods) == 1 else 'Pods.')
            if status == 'PASS' and isinstance(slices, list) and slices and all(_current_text(name) for name in slices) and 'EndpointSlice(s) declare backend addresses' in fact:
                return f'At least {len(slices)} captured ' + ('EndpointSlice declares' if len(slices) == 1 else 'EndpointSlices declare') + ' backend addresses for the Service.'
            if status == 'FAIL' and 'selector matches no current Pods and no EndpointSlice declares backend addresses.' in fact:
                return 'The complete inventory shows neither selected Pods nor declared EndpointSlice addresses for this Service.'
        return None
    observed = evidence.get('observed')
    if not isinstance(observed, str) or len(observed) > 700:
        return None
    if kind == 'selected_vulnerability':
        findings = evidence.get('vulnerabilities')
        if (status == 'FAIL' and _current_list(findings) and findings and all(
                finding.get('severity') in ('HIGH', 'CRITICAL') and
                isinstance(finding.get('image_digest'), str) and
                finding['image_digest'].startswith('sha256:') for finding in findings)
                and observed == 'Trivy found HIGH or CRITICAL package vulnerabilities in the selected Pod image.'):
            return f'The selected Pod image scan recorded {len(findings)} HIGH or CRITICAL package ' + ('vulnerability.' if len(findings) == 1 else 'vulnerabilities.')
        if status == 'PASS' and evidence.get('complete') is True and observed == 'Trivy found no HIGH or CRITICAL package vulnerabilities in the selected Pod image using a fresh database.':
            return 'A complete selected Pod image scan with a fresh database found no HIGH or CRITICAL package vulnerabilities.'
        return None
    if kind == 'selected_secret':
        leaks = evidence.get('secret_leaks')
        if (status == 'FAIL' and _current_list(leaks) and leaks and all(
                isinstance(leak.get('fingerprint'), str) and len(leak['fingerprint']) == 64
                and all(ch in '0123456789abcdef' for ch in leak['fingerprint'])
                and isinstance(leak.get('locations'), list) and leak['locations']
                and isinstance(leak.get('detectors'), list) and leak['detectors'] for leak in leaks)
                and 'likely secret' in observed.lower()):
            return 'Offline detectors found a likely secret in the selected ' + (
                'Flux artifact.' if 'flux_artifact' in check_id else
                'Pod image.' if 'registry_image' in check_id else 'Kubernetes text fields.')
        if status == 'PASS' and evidence.get('complete') is True and observed.startswith((
                'The selected Flux source reported this verified artifact digest.\nBoth offline detectors inspected',
                'Both detectors found no supported secret in the selected Pod image.',
                'The selected Kubernetes text fields held no secret recognized by either offline detector.')):
            return 'Both offline detectors found no supported secret in the selected ' + (
                'Flux artifact bytes.' if 'flux_artifact' in check_id else
                'Pod image bytes.' if 'registry_image' in check_id else 'Kubernetes text fields.')
    return None


def _current_summary(finding):
    check_id, status, evidence = finding['check_id'], finding.get('status'), finding.get('evidence')
    if not isinstance(evidence, dict) or not evidence or status not in ('PASS', 'FAIL', 'UNKNOWN', 'DENIED', 'NOT_APPLICABLE'):
        return None
    if status in ('UNKNOWN', 'DENIED'):
        if (_current_text(evidence.get('reason')) or _current_text(evidence.get('observed'))):
            return reviewed_explanation(check_id, 'The native evidence is incomplete or unavailable, so this result remains uncertain.', status)
        return None
    if status == 'NOT_APPLICABLE':
        if evidence.get('reason') == 'Secret is not a legacy ServiceAccount token':
            return reviewed_explanation(check_id, 'The captured Secret is not a tracked legacy ServiceAccount token.', status)
        if evidence.get('summary') and isinstance(evidence['summary'], str) and '\nThis is a current API declaration, not observed traffic.\n' in evidence['summary']:
            return reviewed_explanation(check_id, 'This object has no applicable native reference for this control.', status)
        return None
    observed = _current_native_observation(check_id, status, evidence)
    return reviewed_explanation(check_id, observed, status) if observed else None


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'k8s':
        return None
    check_id = finding.get('check_id')
    if not isinstance(check_id, str):
        return None
    from .k8s_kubelet_declaration_observed_20261020 import observation as declaration_observation
    declaration = declaration_observation(finding)
    if declaration:
        return declaration
    if check_id in current_review_rows():
        return _current_summary(finding)
    row = review_rows().get(check_id)
    e = finding.get('evidence')
    status = finding.get('status')
    if row is None or not isinstance(e, dict) or not e:
        return None
    if status in ('UNKNOWN', 'DENIED', 'ERROR'):
        # A concrete evaluator/collection reason is required; status is no fact.
        if not _text(e.get('reason'), 500):
            return None
        native = native_observation(finding) if row['renderer'] == 'native' else None
        # Avoid surfacing raw internal paths from missing/malformed-fact errors.
        if e['reason'].startswith(('missing fact:', 'malformed fact:')):
            native = None
        observation = native or 'The required collected evidence is unavailable or unusable, so this setting cannot be assessed.'
        return reviewed_explanation(finding['check_id'], observation, status)
    if status == 'NOT_APPLICABLE':
        reasons = {
            'No container ports declared': 'No container ports are declared, so the low-port restriction has no declared ports to assess.',
            'Not the default/kubernetes Service endpoint slice': 'This EndpointSlice does not belong to the Kubernetes API Service.',
            'PodSecurityPolicy was removed in Kubernetes 1.25': 'This cluster version has removed the legacy PodSecurityPolicy API.',
            'PodSecurityPolicy removed in Kubernetes 1.25+': 'This cluster version has removed the legacy PodSecurityPolicy API.',
            'Pod is not a kube-controller-manager declaration': 'This Pod does not declare the controller-manager component.',
            'Pod is not an etcd declaration': 'This Pod does not declare the etcd storage component.',
            'Different component configuration': 'The supplied configuration belongs to a component other than kubelet.',
            'Different file metadata subject': 'The supplied file metadata describes a different path from the file required by this control.',
            'Binding has no non-system User or Group subjects': 'The binding names no non-system User or Group subject requiring this review.',
            'Binding does not reference cluster-admin': 'This binding does not reference the cluster-admin role.',
            'Linux container control; Windows pod requires its own policy': 'This Pod uses Windows; this control assesses Linux container restrictions.',
            'complete Namespace inventory is empty': 'The complete namespace inventory contains no namespaces to assess.',
            'Service outside selected LoadBalancer set': 'This Service is outside the owner-selected set of LoadBalancer Services.',
        }
        if _text(e.get('reason'), 500):
            return reasons.get(e['reason'], 'The collected resource does not match this control’s applicability requirements.') + ' ' + row['purpose']
        return None
    if status == 'MANUAL':
        observation = _external_observation(finding, row) if row['renderer'] == 'external' else None
        if observation:
            return reviewed_explanation(finding['check_id'], observation, status)
        if _text(e.get('reason'), 500):
            reason = e['reason']
            if reason == 'Paths differ; certificate contents were not read and must be compared by the operator':
                return 'The etcd and API-server declarations name different CA paths; an operator must compare certificate contents. ' + row['purpose']
            if reason.endswith('not present in the supplied kubelet configuration; verify node arguments'):
                return 'The supplied kubelet configuration omits this setting; an operator must inspect node arguments and defaults. ' + row['purpose']
            return 'The collected declaration requires an operator review before a pass/fail conclusion. ' + row['purpose']
        return None
    if status not in ('PASS', 'FAIL'):
        return None
    from .selected_content_observed import observation as selected_content
    selected = selected_content(finding)
    if selected:
        return reviewed_explanation(check_id, selected, status)
    observation = _precise_native(finding, row) if row['renderer'] == 'native' else _external_observation(finding, row)
    return reviewed_explanation(finding['check_id'], observation, status) if observation else None
