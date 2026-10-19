"""Explicitly reviewed interpretations for every registered native GCP check.

The JSON catalog is keyed by exact check ID. Observations are drawn from typed
recorded fields; verdicts never manufacture missing settings or permissions.
"""
import json
from pathlib import Path

CATALOG = json.loads(Path(__file__).with_suffix('.json').read_text())


def reviewed_explanation(check_id, observation, status):
    row = CATALOG.get(check_id)
    if not row or not isinstance(observation, str) or not observation.strip():
        return None
    purpose = row['purpose']
    observation = observation.strip()
    return observation if purpose in observation else observation + ' ' + purpose


def _text(value):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 300 and not any(ord(c) < 32 for c in value)


def _values(values):
    if not isinstance(values, (list, tuple)) or not all(_text(v) for v in values):
        return None
    return ', '.join(values[:2]) + (f' and {len(values) - 2} others' if len(values) > 2 else '')


def _observation(cid, e):
    spec = CATALOG[cid]
    if cid == 'gcp.ports.compute_network_dns_logging_scoped' and _text(e.get('network_reference')):
        reference = e['network_reference']
        prefix = 'https://www.googleapis.com/compute/v1/'
        if reference.startswith(prefix):reference = reference[len(prefix):]
        return 'The DNS policy names network '+reference+'; its matched logging setting was not stored.'
    if cid == 'gcp.appengine.service_version_count':
        keys = ('installed_versions', 'serving_versions', 'approved_installed_maximum', 'approved_serving_maximum')
        if all(type(e.get(k)) is int and e[k] >= 0 for k in keys):
            return f'The service has {e[keys[0]]} installed and {e[keys[1]]} serving versions; approved maxima are {e[keys[2]]} and {e[keys[3]]}.'
    if cid in {'gcp_pci_iam_policy_ca1281da7ab2', 'gcp_pci_iam_policy_9a8ce875703d'}:
        missing, exempt, enabled = e.get('missing_types'), e.get('exempted_required'), _values(e.get('enabled_types'))
        if _values(exempt):
            return 'The audit policy exempts required principals: ' + _values(exempt) + '.'
        if _values(missing):
            names = {'DATA_READ': 'data reads', 'DATA_WRITE': 'data writes', 'ADMIN_READ': 'administrative reads'}
            return 'The complete audit policy does not enable logging for ' + ', '.join(names.get(v, v) for v in missing) + '.'
        if enabled is not None:
            return 'The audit policy enables ' + enabled.replace('DATA_READ', 'data reads').replace('DATA_WRITE', 'data writes') + '.'
    if cid == 'gcp.claude.firewall.public_ingress_common_ports':
        rows = e.get('matching_allow_entries')
        if isinstance(rows, list) and rows:
            labels = [str(row['protocol']).upper() + '/' + row['ports'] for row in rows[:2] if isinstance(row, dict) and _text(row.get('protocol')) and _text(row.get('ports'))]
            if len(labels) == min(len(rows), 2):
                return 'The internet-wide ingress rule includes ' + ', '.join(labels) + ', matching checked administrative or database ports.'
    if cid in {'gcp_logging_detect_t1136', 'gcp_logging_detect_t1546'} and _text(e.get('principal')) and _text(e.get('method')):
        action = 'created a service account' if cid == 'gcp_logging_detect_t1136' else 'created an event trigger'
        return 'The audit event records ' + e['principal'] + ' as the caller that ' + action + '.'
    if cid in {'gcp_logging_detect_t1518', 'gcp_logging_detect_t1614'}:
        rates = e.get('observed_principal_rates')
        if isinstance(rates, dict) and rates and all(_text(k) and type(v) is int and v >= 0 for k, v in rates.items()) and type(e.get('window_seconds')) is int and type(e.get('approved_list_rate')) is int:
            principal = next(iter(rates))
            return f'{principal} made {rates[principal]} matching discovery calls in {e["window_seconds"]} seconds; the approved limit is {e["approved_list_rate"]}.'
    if cid == 'gcp_logging_query_rate_alert':
        if e.get('reason') == 'no qualifying enabled alert in complete inventories':
            return 'No qualifying enabled log-query-rate alert was found in the complete inventory.'
        if _text(e.get('metric')) and _text(e.get('alert')):
            return 'The log-query metric is linked to a configured alert.'
    if cid == 'gcp_cloudsql_failed_attempts_lockout':
        witness = e.get('native_lockout_witness')
        if isinstance(witness, dict) and type(witness.get('configured_builtin_user_count')) is int:
            return f'Managed lock-after-failure settings were recorded for {witness["configured_builtin_user_count"]} built-in MySQL accounts within the approved customer scope.'
    if cid == 'gcp.network.private_service_connect_google_apis' and isinstance(e.get('missing_routes'), list):
        return f'{len(e["missing_routes"])} required private Google API route declarations are missing.'
    if cid == 'gcp_pci_bucket_157fb0c69361' and isinstance(e.get('grants'), list):
        grants = e['grants']
        if any(isinstance(g, (list, tuple)) and len(g) == 2 and g[0] == 'iam' and _text(g[1]) for g in grants):
            return 'The bucket IAM policy records a public read-role grant; individual public members were not stored.'
    event_labels = {
        'gcp_logging_detect_t1110': 'failed authentication',
        'gcp_logging_detect_t1119': 'automated data collection',
        'gcp_logging_detect_t1136': 'service-account creation',
        'gcp_logging_detect_t1490': 'backup deletion or disablement',
        'gcp_logging_detect_t1518': 'software discovery',
        'gcp_logging_detect_t1526': 'cloud-service discovery',
        'gcp_logging_detect_t1546': 'event-trigger creation',
        'gcp_logging_detect_t1614': 'region discovery',
        'gcp_logging_detect_t1619': 'storage object discovery',
        'gcp_logging_detect_t1648': 'serverless invocation',
        'gcp_logging_detect_t1651': 'cloud administration change',
    }
    if cid in event_labels:
        if type(e.get('count')) is int and e['count'] >= 0 and _text(e.get('principal')):
            return f'{e["count"]} matching {event_labels[cid]} events were recorded for {e["principal"]}.'
        if type(e.get('inspected_entries')) is int and e['inspected_entries'] >= 0 and _values(e.get('interval')):
            return f'{e["inspected_entries"]} audit entries were assessed for {event_labels[cid]} during the recorded window.'
    if cid == 'gcp_c5_asset_inventory':
        if type(e.get('checked_assets')) is int:
            return f'{e["checked_assets"]} assets were compared with the independent service inventory.'
        a, b = e.get('missing_service_assets'), e.get('missing_cai_metadata')
        if isinstance(a, list) and isinstance(b, list):
            return f'{len(a)} service assets are absent from Cloud Asset Inventory; {len(b)} listed assets lack required metadata.'
    if cid == 'gcp_logging_scc_findings_alert' and 'findings_without_route' not in e and isinstance(e.get('checked_findings'), list):
        return f'{len(e["checked_findings"])} severe SCC findings were assessed; individual route matches were not stored.'
    if cid == 'gcp_pci_bucket_7dc6cb8c2e05' and e.get('source') in {'IAM', 'effective IAM', 'bucket ACL', 'IAM; uniform access disables ACLs', 'IAM and bucket ACL'}:
        return 'The public-access assessment used ' + e['source'] + '; individual grants were not stored.'
    if cid == 'gcp_c5_key_versions' and e.get('reason') == 'enabled after approved expiry':
        return 'A key version remains enabled after its approved expiry date.'
    if cid == 'gcp_c5_patch_deployment' and e.get('reason') == 'no enabled recurring patch deployment covers this VM':
        return 'No enabled recurring patch deployment covers this VM.'
    reasons = {
        'gcp_c5_key_versions': {'destroyed before approved schedule': 'A key version was destroyed before its approved destruction date.'},
        'gcp_c5_cloud_armor_waf': {'no attached Cloud Armor policy': 'The backend has no attached Cloud Armor policy.'},
        'gcp_pci_backend_service_571fd0bfec67': {'request logging disabled': 'Backend request logging is disabled.'},
        'gcp_c5_workforce_federation': {'pool not ACTIVE': 'The workforce identity pool is not active.'},
    }
    reason = reasons.get(cid, {}).get(e.get('reason')) if isinstance(e.get('reason'), str) else None
    if reason:
        return reason
    if cid == 'gcp_c5_log_isolation' and type(e.get('sink_count')) is int:
        return f'{e["sink_count"]} log sinks were inspected for shared customer-data destinations.'
    custom = spec.get('observation')
    if custom:
        mode, field, label = custom
        v = e.get(field)
        if mode == 'count' and isinstance(v, list):
            return f'{len(v)} {label} were recorded.'
        if mode == 'list':
            values = _values(v)
            if values is not None:
                return f'{label}: {values or "none"}.'
        if mode == 'value' and (type(v) in (str, int, float, bool) or field in e and v is None):
            value = 'not recorded' if v is None else ('enabled' if v else 'disabled') if type(v) is bool else str(v)
            if len(value) <= 300 and not any(ord(c) < 32 for c in value):
                return f'{label}: {value}.'
        if mode == 'binding' and isinstance(v, list):
            if not v:
                return 'No policy grants outside the declared trust lists were recorded; project principals remain separate.'
            first = v[0]
            if isinstance(first, dict) and _text(first.get('principal')) and _text(first.get('role')):
                return f'The policy assigns {first["role"]} to untrusted principal {first["principal"]}' + (f' and records {len(v)-1} other untrusted grants.' if len(v)>1 else '.')
    # Public IAM evidence must explain the actual principal rather than hide it
    # behind the phrase "public-principal declaration".
    for key in spec.get('public_fields', []):
        rows = e.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            members = row.get('members', [row.get('member')])
            if not isinstance(members, list):
                continue
            for principal in members:
                if principal in ('allUsers', 'allAuthenticatedUsers') and _text(row.get('role')):
                    who = 'anyone, including anonymous users' if principal == 'allUsers' else 'any Google-authenticated identity'
                    return f'The policy grants {row["role"]} to {principal} ({who}).'
    from .gcp_observed_evidence import evidence_summary as observed
    from .gcp_remaining_finding_summary import evidence_summary as remaining
    from .gcp_success_observed_evidence import RULES, evidence_summary as success
    finding = dict(provider='gcp', check_id=cid, status=e.pop('__status', 'PASS'), evidence=e)
    observation = observed(finding) or remaining(finding)
    if observation:
        return observation
    # These rules describe explicit values, never a status-dependent conclusion.
    rule = RULES.get(cid, {})
    if rule.get('mode') in {'configured', 'bool', 'string', 'number', 'sequence', 'created', 'firewall', 'sql_flag', 'declared', 'service_state'}:
        return success(dict(finding, status='PASS'))
    return None


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'gcp':
        return None
    cid, status, evidence = finding.get('check_id'), finding.get('status'), finding.get('evidence')
    if not isinstance(cid, str) or cid not in CATALOG or not isinstance(evidence, dict):
        return None
    if not isinstance(status, str):
        return None
    if status in {'UNKNOWN', 'DENIED'}:
        observation = CATALOG[cid]['missing_observation']
    elif status in {'MANUAL', 'NOT_APPLICABLE', 'EMPTY'}:
        from .provider_scope_observed_evidence import provider_scope
        observation = provider_scope(finding)
        if not observation:
            observation = {'MANUAL': 'The recorded assessment needs owner review; its deciding context is incomplete.',
                           'NOT_APPLICABLE': 'The recorded resource is outside this check’s evaluated scope.',
                           'EMPTY': 'No applicable resources were recorded in the assessed scope.'}[status]
    elif status in {'PASS', 'FAIL'}:
        observation = _observation(CATALOG[cid].get('alias_of', cid), dict(evidence, __status=status))
        if not observation:
            # The absence is stated explicitly. A result must not become an
            # invented setting simply because a legacy evaluator omitted it.
            observation = CATALOG[cid]['missing_observation']
    else:
        return None
    return reviewed_explanation(cid, observation, status)
