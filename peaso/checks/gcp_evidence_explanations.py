"""Explicitly reviewed interpretations for every registered native GCP check.

The JSON catalog is keyed by exact check ID. Observations are drawn from typed
recorded fields; verdicts never manufacture missing settings or permissions.
"""
import json
from datetime import datetime, timedelta
from pathlib import Path

_HISTORICAL_CATALOG = json.loads(Path(__file__).with_suffix('.json').read_text())
_CURRENT_REVIEW = json.loads(Path(__file__).with_name('gcp_evidence_explanations_current_20261023.json').read_text())
if set(_HISTORICAL_CATALOG) & set(_CURRENT_REVIEW):
    raise ValueError('GCP current explanation duplicates a historical review')
CATALOG = {**_HISTORICAL_CATALOG, **_CURRENT_REVIEW}


def _historical_activity_observation(check_id, status, evidence):
    """Explain the two native identity-activity outcomes from their bound fields."""
    account = 'gcp.claude.service_account.recently_used'
    key = 'gcp.claude.service_account_key.recently_used'
    if check_id not in (account, key) or evidence.get('threshold_days') != 180:
        return None
    if (check_id == key and status == 'PASS' and isinstance(evidence.get('key_name'), str)
            and isinstance(evidence.get('created_at'), str)
            and type(evidence.get('object_age_days')) is int
            and 0 <= evidence['object_age_days'] <= 180):
        try:
            datetime.fromisoformat(evidence['created_at'])
        except ValueError:
            return None
        return (f'The recorded key is {evidence["object_age_days"]} days old, within the '
                '180-day inactivity threshold; creation date alone does not establish authentication.')
    name = evidence.get('identity_name')
    endpoint = evidence.get('activity_source_endpoint')
    if not isinstance(name, str) or not name.startswith('projects/') or not isinstance(endpoint, str):
        return None
    expected = '/activityTypes/serviceAccountKeyLastAuthentication/activities:query' if check_id == key else '/activityTypes/serviceAccountLastAuthentication/activities:query'
    if not endpoint.startswith('https://policyanalyzer.googleapis.com/v1/projects/') or not endpoint.endswith(expected):
        return None
    try:
        start = datetime.fromisoformat(evidence['observation_start'])
        end = datetime.fromisoformat(evidence['observation_end'])
        last = (datetime.fromisoformat(evidence['reported_last_authentication'])
                if evidence.get('reported_last_authentication') else None)
    except (KeyError, TypeError, ValueError):
        return None
    if start.tzinfo is None or end.tzinfo is None or last is not None and last.tzinfo is None:
        return None
    if start >= end or last is not None and not start <= last <= end:
        return None
    if status == 'PASS' and last is not None:
        days = evidence.get('days_since_reported_authentication')
        if type(days) is int and days == (end - last).days and 0 <= days <= 183:
            return (f'The bound activity observation records authentication {days} '
                    f'{"day" if days == 1 else "days"} before its end.')
    if status == 'FAIL' and end - start > timedelta(days=180):
        if last is not None and end - last > timedelta(days=180):
            return 'The bound activity observation records no authentication within its latest 180 days.'
        if last is None and type(evidence.get('days_without_observed_authentication')) is int and evidence['days_without_observed_authentication'] > 180:
            return 'The bound activity observation records no authentication across more than 180 days.'
    return None


def _current_observation(check_id, status, evidence):
    """Use only a bounded observation emitted by the reviewed native check."""
    if check_id not in _CURRENT_REVIEW:
        return None
    if len(evidence) < 2:
        return None
    if check_id == 'gcp.review.cloud_run.selected_job_image_vulnerabilities':
        findings = evidence.get('vulnerabilities')
        if (isinstance(findings, list) and len(findings) <= 1000
                and evidence.get('association_kind') == 'desired_digest_declaration'
                and evidence.get('runtime_image_proven') is False
                and isinstance(evidence.get('source_requests'), list)
                and evidence['source_requests']):
            if status == 'FAIL' and findings:
                return (f'The selected declared Cloud Run Job image has {len(findings)} recorded '
                        'HIGH or CRITICAL package vulnerability findings.')
            if status == 'PASS' and not findings and evidence.get('coverage_status') == 'COMPLETE':
                return ('The recorded complete scan found no HIGH or CRITICAL package '
                        'vulnerabilities in the selected declared Cloud Run Job image.')
    for field in ('summary', 'observed', 'Observed'):
        value = evidence.get(field)
        if not isinstance(value, str):
            continue
        lines = value.splitlines()
        if (not 1 <= len(lines) <= 3 or any(not line.strip() for line in lines)
                or len(value) > 700 or any(ord(char) < 32 and char not in '\n\t' for char in value)):
            continue
        observation = ' '.join(line.strip() for line in lines)
        if len(observation.split()) <= 85:
            return observation
    return None


def reviewed_explanation(check_id, observation, status):
    row = CATALOG.get(check_id)
    if not row or not isinstance(observation, str) or not observation.strip():
        return None
    purpose = row['purpose']
    from .gcp_natural_evidence import polish_observation
    observation = polish_observation(observation.strip())
    return observation if purpose in observation else observation + ' ' + purpose


def _text(value):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 300 and not any(ord(c) < 32 for c in value)


def _values(values):
    if not isinstance(values, (list, tuple)) or not all(_text(v) for v in values):
        return None
    return ', '.join(values[:2]) + (f' and {len(values) - 2} others' if len(values) > 2 else '')


def _observation(cid, e):
    if cid == 'gcp_cloud_armor_waf_enabled' and e.get('__status') == 'PASS':
        priorities = e.get('waf_rule_priorities')
        backends = e.get('external_backends')
        if (isinstance(e.get('policy'), str) and isinstance(backends, list) and backends
                and all(isinstance(v, str) and v for v in backends)
                and isinstance(priorities, list) and priorities
                and all(type(v) is int and 0 <= v < 2147483647 for v in priorities)):
            return 'The attached external-backend policy declares an enforced preconfigured WAF deny rule.'
        return None
    spec = CATALOG[cid]
    if cid in ('gcp.review.cloudtasks.selected_payload_secret_indicators', 'gcp.review.bigquery.selected_routine_secret_indicators'):
        leaks = e.get('secret_leaks')
        if (e.get('complete') is not True or e.get('coverage') != 'selected_observed_content_only'
                or e.get('credential_validation') != 'not_attempted' or not isinstance(leaks, list)
                or not isinstance(e.get('parts'), list) or not e['parts']):
            return None
        status = e.get('__status')
        if (status == 'FAIL') != bool(leaks):
            return None
        subject = 'selected task body and headers' if '.cloudtasks.' in cid else 'selected routine definition'
        return ('A likely secret was detected in the ' + subject + '.' if leaks else
                'Both offline detectors found no supported secret in the ' + subject + '.')
    if cid == 'gcp.review.sourcerepo.selected_file_secret_indicators':
        if (e.get('coverage') != 'selected_files_at_advertised_commit_only'
                or e.get('complete') is not True or not isinstance(e.get('secret_leaks'), list)
                or e.get('credential_validation') != 'not_attempted'):
            return None
        return ('A likely secret was detected in the selected repository files at the advertised commit.'
                if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the selected repository files at the advertised commit.')
    if cid in ('gcp.ports.sql_instance_require_ssl_enabled', 'gcp.ports.reference_sql_ssl_connections'):
        mode = e.get('sslMode', e.get('ssl_mode'))
        if mode == 'ENCRYPTED_ONLY':
            return 'SQL connections require encryption.'
        if mode == 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED':
            return 'SQL connections require encryption and a trusted client certificate.'
        if mode == 'ALLOW_UNENCRYPTED_AND_ENCRYPTED':
            return 'SQL permits both encrypted and unencrypted connections.'
        if e.get('deciding_field') == 'settings.ipConfiguration.requireSsl' and type(e.get('legacy_require_ssl')) is bool:
            return ('The legacy SQL setting requires encrypted client connections.' if e['legacy_require_ssl'] else
                    'The legacy SQL setting does not require encrypted client connections.')
    if cid in ('gcp.review.cloudbuild.artifact_secret_indicators', 'gcp.review.clouddeploy.release_source_secret_indicators'):
        artifact = cid == 'gcp.review.cloudbuild.artifact_secret_indicators'
        expected = 'observed_manifest_generations_only' if artifact else 'observed_object_generation_only'
        if (not isinstance(e.get('secret_leaks'), list) or e.get('coverage') != expected
                or e.get('credential_validation') != 'not_attempted'
                or e.get('historical_build_bytes' if artifact else 'historical_release_bytes') != 'not_established'):
            return None
        subject = 'the pinned artifacts in the observed Cloud Build output manifest' if artifact else 'the observed Cloud Deploy source archive generation'
        return ('A likely secret was detected in ' + subject + '.' if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in ' + subject + '.')
    if cid == 'gcp.review.appengine.deployment_source_secret_indicators':
        if (not isinstance(e.get('secret_leaks'), list)
                or e.get('coverage') != 'complete_native_deployment_files_manifest_only'
                or type(e.get('files')) is not int or e['files'] < 1):
            return None
        return ('A likely secret was detected in the hash-matched App Engine deployment source files.'
                if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the hash-matched App Engine deployment source files.')
    if cid == 'gcp.review.cloudbuild.stored_log_secret_indicators':
        if (not isinstance(e.get('secret_leaks'), list) or e.get('complete') is not True
                or e.get('coverage') != 'observed_object_generation_only'
                or e.get('historical_build_log_completion') != 'not_established'):
            return None
        return ('A likely secret was detected in the observed Cloud Build stored log generation.'
                if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the observed Cloud Build stored log generation.')
    if cid == 'gcp.compute.os_config_fixable_vulnerabilities':
        count, assessed = e.get('fixable_finding_count'), e.get('assessment_time')
        if type(count) is not int or count < 0 or not _text(assessed):
            return None
        return f'The OS Config assessment at {assessed} reports {count} fixable known vulnerability findings for this VM.'
    content_labels = {
        'gcp.review.function.resolved_source_archive_secret_indicators': 'the function’s resolved source archive',
        'gcp.review.artifactregistry.selected_file_secret_indicators': 'the selected Artifact Registry package file',
        'gcp.review.composer.dag_source_secret_indicators': 'the observed Composer DAG source file generations',
    }
    if cid in content_labels:
        if not isinstance(e.get('secret_leaks'), list) or e.get('credential_validation') != 'not_attempted':
            return None
        return ('A likely secret was detected in ' + content_labels[cid] + '.' if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in ' + content_labels[cid] + '.')
    if cid == 'gcp.review.dataform.selected_file_secret_indicators':
        if e.get('complete') is not True or not isinstance(e.get('secret_leaks'), list):
            return None
        return ('A likely secret was detected in the explicitly selected Dataform file.'
                if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the returned selected Dataform file.')
    extra_secret_labels = {
        'gcp.review.scheduler_job.literal_target_secret_indicators': 'returned Scheduler target literals',
        'gcp.review.app_engine_version.literal_environment_secret_indicators': 'returned App Engine environment values',
        'gcp.review.workflow.deployed_source_secret_indicators': 'returned deployed workflow source',
    }
    if cid in extra_secret_labels:
        if (not isinstance(e.get('secret_leaks'), list) or not isinstance(e.get('surfaces'), list)
                or not e['surfaces'] or e.get('credential_validation') != 'not_attempted'):
            return None
        return ('A likely secret was detected in the ' + extra_secret_labels[cid] + '.' if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the ' + extra_secret_labels[cid] + '.')
    if cid == 'gcp.review.storage.selected_archive_secret_indicators':
        if e.get('complete') is not True or not isinstance(e.get('secret_leaks'), list):
            return None
        return ('A likely secret was detected in a text member of the selected Cloud Storage archive.'
                if e['secret_leaks'] else
                'Both offline detectors finished on every regular text member of the complete selected archive without finding a supported secret.')
    if cid == 'gcp.review.artifact_image.content_secret_indicators':
        if (e.get('complete') is not True or not isinstance(e.get('secret_leaks'), list)
                or e.get('credential_validation') != 'not_attempted'):
            return None
        return ('A likely secret was detected in the selected immutable image configuration or a layer.'
                if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the inspected image configuration and layers.')
    if cid == 'gcp.review.storage.selected_object_secret_indicators':
        if e.get('complete') is not True or not isinstance(e.get('secret_leaks'), list):
            return None
        return ('A likely secret was detected in an explicitly selected Cloud Storage text object.'
                if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the complete selected text object.')
    if cid == 'gcp.review.logging.application_log_secret_indicators':
        sample = e.get('sample')
        if (not isinstance(sample, dict) or not isinstance(sample.get('scans'), list)
                or not sample['scans'] or not isinstance(e.get('secret_leaks'), list)):
            return None
        return ('A likely secret was detected in the sampled application log messages.'
                if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the sampled application log messages.')
    if cid == 'gcp.review.gke_workload.literal_configuration_secret_indicators':
        if (not isinstance(e.get('secret_leaks'), list) or not isinstance(e.get('surfaces'), list)
                or e.get('credential_validation') != 'not_attempted'):
            return None
        return ('A likely secret was detected in the returned GKE ConfigMap or Pod literal values.'
                if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the returned GKE ConfigMap or Pod literal values.')
    if cid.startswith('gcp.review.') and cid.endswith('.literal_configuration_secret_indicators'):
        if e.get('complete') is not True or not isinstance(e.get('secret_leaks'), list):
            return None
        labels = {
            'instance': 'VM metadata and startup scripts',
            'instance_template': 'instance-template metadata', 'project': 'project common metadata',
            'cloudrun_service': 'Cloud Run service literals', 'cloudrun_job': 'Cloud Run job literals',
            'cloudbuild_trigger': 'inline Cloud Build trigger configuration',
            'cloudbuild_build': 'returned Cloud Build configuration',
            'dataflow_job': 'returned Dataflow job environment', 'batch_job': 'returned Batch task literals',
            'dataproc_cluster': 'Dataproc cluster properties and metadata',
            'dataproc_job': 'returned Dataproc job literals',
            'composer_environment': 'Composer environment and Airflow configuration literals',
            'workbench_instance': 'Workbench metadata literals',
        }
        label = labels.get(cid.split('.')[2], 'returned literal configuration')
        return ('A likely secret was detected in the ' + label + '.' if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the ' + label + '.')
    if cid == 'gcp.review.function.literal_environment_secret_indicators':
        if e.get('complete') is not True or not isinstance(e.get('secret_leaks'), list):
            return None
        return ('A likely secret was detected in the function’s literal environment values.'
                if e['secret_leaks'] else
                'Both offline detectors finished without finding a supported secret in the returned runtime and build environment values.')
    if cid == 'gcp.identity.non_service_account_mfa':
        enrolled, enforced = e.get('isEnrolledIn2Sv'), e.get('isEnforcedIn2Sv')
        if type(enrolled) is bool and type(enforced) is bool:
            return ('Two-step verification enrollment is ' + ('enabled' if enrolled else 'disabled')
                    + ' and enforcement is ' + ('enabled.' if enforced else 'disabled.'))
        return None
    if cid == 'gcp_pci_bucket_157fb0c69361':
        inherited = e.get('inherited_public_read_grants')
        if isinstance(inherited, list) and inherited and all(
                isinstance(row, dict) and _text(row.get('scope')) and _text(row.get('role')) for row in inherited):
            return 'An ancestor IAM policy grants public read access to this bucket.'
        scopes = e.get('policy_scopes')
        if isinstance(scopes, list) and scopes and all(_text(scope) for scope in scopes):
            return 'No public read grant was found in the collected bucket ACLs and IAM hierarchy.'
    if cid in {'gcp.review.workbench.public_ip_disabled', 'gcp.review.workbench.root_access_disabled'}:
        if type(e.get('disabled')) is not bool:
            return None
        if cid.endswith('public_ip_disabled') and e.get('setting') == 'gceSetup.disablePublicIp':
            return ('The Workbench instance disables public IP assignment.' if e['disabled'] else
                    'The Workbench instance permits public IP assignment.')
        if cid.endswith('root_access_disabled') and e.get('setting') == 'gceSetup.metadata.notebook-disable-root':
            return 'Workbench notebook root access is ' + ('disabled.' if e['disabled'] else 'enabled.')
        return None
    from .gcp_natural_evidence import natural_observation, natural_extra
    prose = natural_extra(cid,e) or natural_observation(cid,e,spec)
    if prose:return prose
    if cid == 'gcp.ports.compute_network_dns_logging_scoped' and _text(e.get('network_reference')):
        reference = e['network_reference']
        prefix = 'https://www.googleapis.com/compute/v1/'
        if reference.startswith(prefix):reference = reference[len(prefix):]
        return 'The DNS policy names network '+reference+'; its matched logging setting was not stored.'
    if cid == 'gcp.appengine.service_version_count':
        keys = ('installed_versions', 'serving_versions', 'approved_installed_maximum', 'approved_serving_maximum')
        if all(type(e.get(k)) is int and e[k] >= 0 for k in keys):
            installed, serving, installed_limit, serving_limit = (e[k] for k in keys)
            return f'The service has {installed} installed '+('version' if installed == 1 else 'versions')+f' (limit {installed_limit}) and {serving} serving '+('version' if serving == 1 else 'versions')+f' (limit {serving_limit}).'
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
        if mode in ('list','value') and spec.get('prose'):return None
        v = e.get(field)
        if mode == 'count' and isinstance(v, list):
            if not v:return 'No '+label+' were recorded.'
            singular={'qualifying age-based artifact deletion policies':'qualifying age-based artifact deletion policy','deviations from the approved network topology':'deviation from the approved network topology','unapproved IAM bindings':'unapproved IAM binding','unregistered installed packages':'unregistered installed package','unapproved installed packages':'unapproved installed package','IAM grants overdue for removal':'IAM grant overdue for removal','IAM bindings missing required contextual attributes':'IAM binding missing required contextual attributes','IAM grants missing required expiry conditions':'IAM grant missing a required expiry condition','missing required PSC endpoint or private DNS declarations':'missing required PSC endpoint or private DNS declaration'}
            return f'The assessment found {len(v)} '+(singular.get(label,label) if len(v)==1 else label)+'.'
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
    from .gcp_cloudrun_job_image_observed_20261020 import observation as job_image_observation
    job_image = job_image_observation(finding)
    if job_image:
        return job_image
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
        historical_activity = _historical_activity_observation(cid, status, evidence)
        if historical_activity:
            return reviewed_explanation(cid, historical_activity, status)
        current = _current_observation(cid, status, evidence)
        if current:
            return reviewed_explanation(cid, current, status)
        from .gcp_workbench_head3_observed_20261020 import observation as head3
        configured = head3(finding)
        if configured:
            return reviewed_explanation(cid, configured, status)
        from .public_source_secret_observed_20261020 import observation as public_source
        grouped = public_source(finding)
        if grouped:
            return grouped
        from .selected_configuration_content_observed_20261020 import observation as selected_observation
        observation = selected_observation(finding) or _observation(CATALOG[cid].get('alias_of', cid), dict(evidence, __status=status))
        if not observation:
            # The absence is stated explicitly. A result must not become an
            # invented setting simply because a legacy evaluator omitted it.
            observation = CATALOG[cid]['missing_observation']
    else:
        return None
    return reviewed_explanation(cid, observation, status)
