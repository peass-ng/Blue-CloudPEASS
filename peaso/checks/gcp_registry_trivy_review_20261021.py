"""Selected standalone immutable registry image vulnerability evidence."""
from copy import deepcopy

from peaso import container_image_archive_20261020 as archive
from peaso import trivy_container_runner_20261020 as trivy
from peaso import gcp_image_selection_20261021 as selection_api

SCHEMA = 'gcp-selected-registry-image-vulnerabilities-record-v1'
KEYS = {'schema', 'scope', 'selection', 'image', 'status', 'complete',
        'scan_complete', 'coverage_status', 'database_fresh', 'findings',
        'source_requests', 'association_kind', 'runtime_image_proven'}
FINDING_KEYS = {'vulnerability_id', 'severity', 'package_types', 'package',
                'version', 'fixed_in', 'fix_status', 'classes', 'image_digest'}


def project(selection, scope, scan):
    """Strip scanner internals; preserve typed positives on incomplete coverage."""
    return {'schema': SCHEMA, 'scope': scope, 'selection': deepcopy(selection),
            'image': deepcopy(scan.get('image')), 'status': scan.get('status'),
            'complete': scan.get('complete'), 'scan_complete': scan.get('scan_complete'),
            'coverage_status': scan.get('coverage_status'),
            'database_fresh': scan.get('database', {}).get('fresh') is True,
            'findings': deepcopy(scan.get('findings', [])),
            'source_requests': deepcopy(scan.get('source_requests', [])),
            'association_kind': scan.get('association_kind'),
            'runtime_image_proven': scan.get('runtime_image_proven')}


def evaluate(record, index):
    """Return UNKNOWN for unbound/malformed evidence, never certify stale clean."""
    try:
        if type(record) is not dict or set(record) != KEYS or record['schema'] != SCHEMA:
            raise ValueError('closed_vulnerability_record_required')
        scope, selection = record['scope'], record['selection']
        if scope != index['scope'] or selection not in selection_api.selections({selection_api.OPTION:index['selections']}, [scope]):
            raise ValueError('selected_native_declaration_required')
        image = archive.identity(record['image'])
        if image['provider'] != 'gcp' or image['scope'] != scope or image['immutable_reference'] != selection:
            raise ValueError('exact_image_identity_required')
        if record['association_kind'] != 'selected_registry_digest' or record['runtime_image_proven'] is not False:
            raise ValueError('declaration_only_required')
        ids = record['source_requests']
        ledger = index['source_requests']
        if (type(ids) is not list or len(ids) < 9 or len(ids) != len(set(ids))
                or type(ledger) is not list or len({r.get('id') for r in ledger}) != len(ledger)
                or not set(ids) <= {r.get('id') for r in ledger}):
            raise ValueError('native_request_provenance_required')
        if any(r.get('status') != 'collected' or r.get('method') != 'GET'
               for r in ledger if r.get('id') in ids):
            raise ValueError('native_read_incomplete')
        findings = record['findings']
        if type(findings) is not list or len(findings) > 1000:
            raise ValueError('bounded_findings_required')
        keys = set()
        for finding in findings:
            if type(finding) is not dict or set(finding) != FINDING_KEYS:
                raise ValueError('closed_finding_required')
            if (finding['severity'] not in ('HIGH', 'CRITICAL')
                    or finding['image_digest'] != image['manifest_digest']
                    or type(finding['package']) is not str
                    or type(finding['version']) is not str
                    or type(finding['vulnerability_id']) is not str
                    or trivy.VULN_ID.fullmatch(finding['vulnerability_id']) is None
                    or trivy.TEXT.fullmatch(finding['package']) is None
                    or trivy.TEXT.fullmatch(finding['version']) is None
                    or type(finding['fixed_in']) is not list
                    or len(finding['fixed_in']) > 64
                    or any(type(fix) is not str or trivy.FIX.fullmatch(fix) is None
                           for fix in finding['fixed_in'])
                    or type(finding['classes']) is not list
                    or not finding['classes']
                    or any(c not in ('os-pkgs', 'lang-pkgs') for c in finding['classes'])
                    or type(finding['package_types']) is not list
                    or not finding['package_types']
                    or any(type(p) is not str or trivy.TEXT.fullmatch(p) is None
                           for p in finding['package_types'])):
                raise ValueError('typed_high_critical_finding_required')
            key = (finding['package'], finding['version'], finding['vulnerability_id'])
            if key in keys:
                raise ValueError('duplicate_vulnerability')
            keys.add(key)
        status = record['status']
        if status not in ('FAIL', 'PASS', 'UNKNOWN') or type(record['complete']) is not bool:
            raise ValueError('typed_scan_status_required')
        if (status == 'FAIL') != bool(findings):
            raise ValueError('positive_status_mismatch')
        if status == 'PASS' and not (record['complete'] is True
                and record['scan_complete'] is True and record['database_fresh'] is True
                and record['coverage_status'] == 'COMPLETE'):
            raise ValueError('stale_or_incomplete_pass_refused')
        if status == 'UNKNOWN' and (record['complete'] is True or findings):
            raise ValueError('unknown_scan_inconsistent')
        return status, {'image_digest': image['manifest_digest'],
                        'vulnerabilities': deepcopy(findings),
                        'source_requests': deepcopy(ids),
                        'association_kind': 'selected_registry_digest',
                        'runtime_image_proven': False,
                        'coverage_status': record['coverage_status']}
    except (KeyError, ValueError, TypeError, AttributeError):
        return 'UNKNOWN', {'vulnerabilities': [], 'coverage_status': 'UNKNOWN'}

CHECK_ID='gcp.review.artifact_image.selected_image_vulnerabilities'
KIND='artifact_selected_image_vulnerabilities'
OPTION='selected_gcp_registry_image_vulnerabilities'
DECLARATION={'id':CHECK_ID,'provider':'gcp','category':'hardening','kind':KIND,
    'title':'Selected registry image has no HIGH or CRITICAL package vulnerabilities',
    'severity':'high','control':'security_configuration',
    'remediation':'Update affected packages, rebuild the image and select the new immutable digest.',
    'target':'resource','dependencies':(KIND,),'allow_incomplete_failure':True}
DESCRIPTION={'description':'Reads a selected immutable registry image and scans its verified layers with Trivy.',
    'evaluated':['native project, repository and DockerImage identity before and after download',
                 'manifest, config, compressed layer and rootfs digests',
                 'fresh complete offline HIGH and CRITICAL package findings'],
    'pass_when':'The selected image has no HIGH or CRITICAL findings in a fresh complete scan.',
    'fail_when':'The bound image has at least one typed HIGH or CRITICAL package finding.',
    'not_applicable_when':None}
REFERENCES=('https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.dockerImages/get',
            'https://docs.cloud.google.com/artifact-registry/docs/access-control')


def evaluate_item(item,index):
    try:
        context=index['context'];scope=context['scope'];metadata=context['metadata']
        if context['provider']!='gcp':raise ValueError('foreign_provider')
        collection,=[r for r in index['collections'][KIND] if r['scope']==scope]
        if collection['status'] not in ('collected','partial') or item not in collection['items']:
            raise ValueError('unbound_collection')
        marker=item['RegistryImageVulnerabilityReview'];reference=marker['immutable_reference']
        if item['name']!=reference or item['_resource_id']!=reference or item['native_id']!=reference:
            raise ValueError('image_identity_mismatch')
        record=marker['vulnerability_record']
        if record is None:
            return 'UNKNOWN',{'Observed':'The selected image has no recorded package scan. Its vulnerability state is unclear.'}
        if record['selection']!=reference or set(record['source_requests'])!=set(marker['source_requests']):
            raise ValueError('source_binding_mismatch')
        status,evidence=evaluate(record,{'scope':scope,'selections':metadata[OPTION],
                                        'source_requests':marker['source_ledger']})
        if status=='FAIL':
            evidence['Observed']='The selected immutable image has a recorded HIGH or CRITICAL package vulnerability. If deployed, these bytes could expose a service to that weakness. Service data may be affected.'
        elif status=='PASS':
            evidence['Observed']='The selected immutable image has no HIGH or CRITICAL findings in its fresh completed package scan. Services using these bytes may avoid those known package weaknesses. This helps protect their data.'
        else:
            evidence['Observed']='The selected image lacks a fresh, complete package vulnerability result. Its package vulnerability state is unclear.'
        return status,evidence
    except (KeyError,ValueError,TypeError,AttributeError):
        return 'UNKNOWN',{'Observed':'The selected image lacks matching native identity or package scan evidence. Its vulnerability state is unclear.'}


def install(registry):
    if CHECK_ID in {c.id for c in registry.CHECKS}:
        raise RuntimeError('duplicate_registry_image_check')
    from .provider_content_native_cases_20261021 import native_case
    from .fixtures import CASES
    case = native_case(CHECK_ID)
    declaration=dict(DECLARATION);ident=declaration.pop('id')
    registry.register(ident,**declaration)(evaluate_item)

    CASES[CHECK_ID] = case
