"""Selected standalone immutable registry image vulnerability evidence."""
from copy import deepcopy
from peaso.snapshot import FrozenDict, FrozenList

from peaso import container_image_archive_20261020 as archive
from peaso import trivy_container_runner_20261020 as trivy
from peaso import gcp_image_selection_20261021 as selection_api
from peaso import oci_index_20261021 as oci_index
from peaso.collectors import gcp_image_secret_indicators as native

SCHEMA = 'gcp-selected-registry-image-vulnerabilities-record-v1'
KEYS = {'schema', 'scope', 'selection', 'image', 'status', 'complete',
        'scan_complete', 'coverage_status', 'database_fresh', 'findings',
        'source_requests', 'association_kind', 'runtime_image_proven'}
FINDING_KEYS = {'vulnerability_id', 'severity', 'package_types', 'package',
                'version', 'fixed_in', 'fix_status', 'classes', 'image_digest'}


def project(selection, scope, scan):
    """Strip scanner internals; preserve typed positives on incomplete coverage."""
    record = {'schema': SCHEMA, 'scope': scope, 'selection': deepcopy(selection),
            'image': deepcopy(scan.get('image')), 'status': scan.get('status'),
            'complete': scan.get('complete'), 'scan_complete': scan.get('scan_complete'),
            'coverage_status': scan.get('coverage_status'),
            'database_fresh': scan.get('database', {}).get('fresh') is True,
            'findings': deepcopy(scan.get('findings', [])),
            'source_requests': deepcopy(scan.get('source_requests', [])),
            'association_kind': scan.get('association_kind'),
            'runtime_image_proven': scan.get('runtime_image_proven')}
    if 'graph' in scan:
        record['graph'] = deepcopy(scan['graph'])
    return record


def evaluate_index(record, index):
    """Bind child CVEs to one selected parent and its ordered verified reads."""
    try:
        if type(record) is not dict or set(record) != KEYS | {'graph'} or record['schema'] != SCHEMA:
            raise ValueError('closed_index_record_required')
        scope, selection = record['scope'], record['selection']
        if (scope != index['scope'] or selection not in selection_api.selections(
                {selection_api.OPTION: index['selections']}, [scope])
                or record['association_kind'] != 'selected_registry_digest'
                or record['runtime_image_proven'] is not False):
            raise ValueError('selected_parent_required')
        uri, repo, digest, _ = native.parse_image_uri(selection)
        image = record['image']
        if (type(image) is not dict or image != {'provider': 'gcp', 'scope': scope,
                'immutable_reference': selection, 'manifest_digest': digest}):
            raise ValueError('parent_identity_required')
        graph = record['graph']
        if (type(graph) is not dict or set(graph) != {'parent_digest','media_type',
                'parent_source_request','children','tail_reads','complete'}
                or graph['parent_digest'] != digest or graph['media_type'] not in oci_index.INDEX_TYPES
                or type(graph['complete']) is not bool or type(graph['children']) is not list
                or not 1 <= len(graph['children']) <= oci_index.MAX_CHILDREN
                or type(graph['tail_reads']) is not list
                or len(graph['tail_reads']) > archive.MAX_LAYERS + 2
                or graph['complete'] and graph['tail_reads']):
            raise ValueError('bounded_parent_graph_required')
        ids, ledger = record['source_requests'], index['source_requests']
        if (type(ids) is not list or len(ids) != len(set(ids)) or type(ledger) is not list
                or len({r.get('id') for r in ledger}) != len(ledger)
                or {r.get('id') for r in ledger} != set(ids)):
            raise ValueError('native_receipt_set_required')
        metadata = [r for r in ledger if r.get('operation') == 'artifactregistry_selected_image_metadata_get']
        reads = [r for r in ledger if r.get('operation') == 'artifactregistry.registry_content_get']
        if (len(metadata) != 6 or not reads or reads[0].get('id') != graph['parent_source_request']
                or reads[0].get('category') != 'manifests' or reads[0].get('digest') != digest
                or any(r.get('status') != 'collected' or r.get('http_status') != 200
                       for r in metadata)):
            raise ValueError('native_parent_receipts_required')
        expected = [('manifests', digest, graph['parent_source_request'])]
        child_digests, complete, scan_complete, fresh = set(), graph['complete'], graph['complete'], True
        for child in graph['children']:
            if (type(child) is not dict or set(child) != {'digest','size','mediaType','platform',
                    'config','layers','source_requests','status','complete',
                    'scan_complete','database_fresh'}
                    or child['mediaType'] not in oci_index.LEAF_TYPES
                    or type(child['digest']) is not str or archive.DIGEST.fullmatch(child['digest']) is None
                    or child['digest'] in child_digests or type(child['size']) is not int
                    or not 0 < child['size'] <= archive.MAX_MANIFEST):
                raise ValueError('verified_child_descriptor_required')
            child_digests.add(child['digest'])
            oci_index._platform(child['platform'])
            config = archive.descriptor(child['config'], archive.CONFIGS, archive.MAX_CONFIG)
            layers = child['layers']
            if type(layers) is not list or not 1 <= len(layers) <= archive.MAX_LAYERS:
                raise ValueError('bounded_child_layers_required')
            layers = [archive.descriptor(part, archive.LAYERS, archive.MAX_LAYER) for part in layers]
            if (sum(part['size'] for part in [config] + layers) > archive.MAX_COMPRESSED
                    or child['status'] not in ('PASS','FAIL','UNKNOWN')
                    or type(child['complete']) is not bool
                    or type(child['scan_complete']) is not bool
                    or type(child['database_fresh']) is not bool
                    or type(child['source_requests']) is not list
                    or len(child['source_requests']) != 2 + len(layers)):
                raise ValueError('child_scan_proof_required')
            expected.extend([(kind, part, rid) for (kind, part), rid in zip(
                [('manifests', child['digest']), ('blobs', config['digest'])] +
                [('blobs', layer['digest']) for layer in layers], child['source_requests'])])
            complete = complete and child['complete'] and child['status'] in ('PASS','FAIL')
            scan_complete = scan_complete and child['scan_complete']
            fresh = fresh and child['database_fresh']
        tail = graph['tail_reads']
        for position, entry in enumerate(tail):
            if (type(entry) is not dict or set(entry) != {'id','category','digest'}
                    or entry['category'] != ('manifests' if position == 0 else 'blobs')
                    or type(entry['digest']) is not str
                    or archive.DIGEST.fullmatch(entry['digest']) is None):
                raise ValueError('unverified_tail_read')
            expected.append((entry['category'], entry['digest'], entry['id']))
        if len(reads) < len(expected) or len(reads) > len(expected) + (not graph['complete']):
            raise ValueError('child_read_count_mismatch')
        for receipt, (category, child_digest, rid) in zip(reads, expected):
            if (receipt.get('id') != rid or receipt.get('category') != category
                    or receipt.get('digest') != child_digest
                    or receipt.get('method') != 'GET' or receipt.get('status') != 'collected'
                    or receipt.get('http_status') != 200 or receipt.get('scope') != scope):
                raise ValueError('child_read_sequence_mismatch')
        if len(reads) > len(expected) and (reads[-1].get('category') !=
                ('blobs' if tail else 'manifests')
                or reads[-1].get('status') == 'collected' or reads[-1].get('scope') != scope
                or reads[-1].get('method') != 'GET'):
            raise ValueError('unexpected_extra_read')
        findings = record['findings']
        if type(findings) is not list or len(findings) > trivy.MAX_FINDINGS:
            raise ValueError('bounded_child_findings_required')
        keys = set()
        for finding in findings:
            if type(finding) is not dict or set(finding) != FINDING_KEYS:
                raise ValueError('closed_child_finding_required')
            if (finding['severity'] not in ('HIGH','CRITICAL')
                    or finding['image_digest'] not in child_digests
                    or type(finding['package']) is not str or trivy.TEXT.fullmatch(finding['package']) is None
                    or type(finding['version']) is not str or trivy.TEXT.fullmatch(finding['version']) is None
                    or type(finding['vulnerability_id']) is not str
                    or trivy.VULN_ID.fullmatch(finding['vulnerability_id']) is None
                    or type(finding['fixed_in']) is not list or len(finding['fixed_in']) > 64
                    or any(type(fix) is not str or trivy.FIX.fullmatch(fix) is None for fix in finding['fixed_in'])
                    or type(finding['classes']) is not list or not finding['classes']
                    or any(c not in ('os-pkgs','lang-pkgs') for c in finding['classes'])
                    or type(finding['package_types']) is not list or not finding['package_types']
                    or any(type(p) is not str or trivy.TEXT.fullmatch(p) is None for p in finding['package_types'])):
                raise ValueError('typed_child_cve_required')
            key = (finding['image_digest'], finding['package'], finding['version'],
                   finding['vulnerability_id'])
            if key in keys:
                raise ValueError('duplicate_child_cve')
            keys.add(key)
        for child in graph['children']:
            has_finding = any(finding['image_digest'] == child['digest'] for finding in findings)
            if ((child['status'] == 'FAIL') != has_finding
                    or child['status'] == 'PASS' and not (child['complete'] and child['scan_complete']
                        and child['database_fresh'])
                    or child['status'] == 'UNKNOWN' and child['complete']):
                raise ValueError('child_status_findings_mismatch')
        complete = complete and fresh
        status = record['status']
        if ((status == 'FAIL') != bool(findings) or status not in ('PASS','FAIL','UNKNOWN')
                or type(record['complete']) is not bool
                or record['complete'] != complete or record['scan_complete'] is not scan_complete
                or record['database_fresh'] is not fresh
                or record['coverage_status'] != ('COMPLETE' if complete else 'UNKNOWN')
                or status == 'PASS' and not (record['complete'] and complete and fresh
                    and record['scan_complete'] is True and record['coverage_status'] == 'COMPLETE')
                or status == 'UNKNOWN' and (findings or record['complete'])):
            raise ValueError('index_verdict_mismatch')
        return status, {'image_digest': digest, 'vulnerabilities': deepcopy(findings),
            'source_requests': deepcopy(ids), 'association_kind': 'selected_registry_digest',
            'runtime_image_proven': False, 'coverage_status': record['coverage_status']}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return 'UNKNOWN', {'vulnerabilities': [], 'coverage_status': 'UNKNOWN'}


def evaluate(record, index):
    """Return UNKNOWN for unbound/malformed evidence, never certify stale clean."""
    if type(record) is dict and 'graph' in record:
        return evaluate_index(record, index)
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


def _trusted_json_copy(value):
    """Admit only exact JSON and the engine's sealed snapshot containers."""
    kind = type(value)
    if kind in (dict, FrozenDict):
        if any(type(key) is not str for key in value):
            raise ValueError('unsupported_json_key')
        return {key: _trusted_json_copy(member) for key, member in value.items()}
    if kind in (list, FrozenList):
        return [_trusted_json_copy(member) for member in value]
    if kind in (str, int, float, bool, type(None)):
        return value
    raise ValueError('unsupported_json_type')


def evaluate_item(item,index):
    try:
        item = _trusted_json_copy(item)
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
        status,evidence=evaluate(record,{'scope':scope,'selections':_trusted_json_copy(metadata[OPTION]),
                                        'source_requests':marker['source_ledger']})
        if status=='FAIL':
            evidence['Observed']='The selected immutable image contains HIGH or CRITICAL package vulnerabilities.'
        elif status=='PASS':
            evidence['Observed']='Trivy found no HIGH or CRITICAL package vulnerabilities in the selected immutable image using a fresh database.'
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
