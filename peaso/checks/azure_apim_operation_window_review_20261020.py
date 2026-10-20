"""Research only; customer analysis parameters preclude automatic CSPM admission."""
import re
from peaso.collectors import azure_apim_operation_window_20261020 as source


def bound(item, index):
    context = index['context']; metadata = context['metadata']; scope = context['scope']
    if (context['provider'] != 'azure' or not isinstance(scope, str) or not source.SCOPE.fullmatch(scope)
            or metadata[source.KIND + '_authorized'] is not True):
        raise ValueError()
    capture = metadata[source.KIND + '_capture']; tenant = metadata[source.KIND + '_tenant']
    if (not isinstance(capture, str) or not re.fullmatch('[0-9a-f]{32}', capture)
            or not isinstance(tenant, str) or not re.fullmatch(source.GUID, tenant, re.I)
            or 'tenant_id' in metadata and str(metadata['tenant_id']).casefold() != tenant.casefold()
            or 'tenant_verified' in metadata and metadata['tenant_verified'] is not True
            or 'credential_context_id' in metadata and metadata['credential_context_id'] != capture
            or 'customer_context_id' in metadata and metadata['customer_context_id'] != 'scan-local:' + capture):
        raise ValueError()
    own, = [r for r in index['collections'][source.KIND] if r.get('scope') == scope]
    selected = metadata[source.KIND + '_selection'][scope]
    if (own['type'] != source.KIND or own['service'] != 'Microsoft.ApiManagement' or own['status'] != 'collected'
            or not isinstance(selected, list) or not 1 <= len(selected) <= source.MAX_TARGETS
            or len(set(selected)) != len(selected)
            or any(not isinstance(v, str) or not re.fullmatch(source.KIND + ':[0-9a-f]{64}', v) for v in selected)
            or len(own['items']) != len(selected) or {r['id'] for r in own['items']} != set(selected)
            or sum(r == item for r in own['items']) != 1):
        raise ValueError()
    marker = item[source.MARKER]; proof = item['_provenance']; ident = item['id']
    if (set(item) != {'id', source.MARKER, '_provenance'}
            or set(marker) != {'schema', 'identity', 'scope', 'capture', 'complete', 'window_start', 'window_end',
                'operation_count', 'threshold_percent', 'summary', 'source_requests'}
            or marker['schema'] != source.SCHEMA or marker['identity'] != ident or marker['scope'] != scope
            or marker['capture'] != capture or marker['complete'] is not True
            or (source.instant(marker['window_end']) - source.instant(marker['window_start'])).total_seconds() != source.WINDOW_SECONDS
            or type(marker['operation_count']) is not int or not 2 <= marker['operation_count'] <= 32
            or type(marker['threshold_percent']) is not int or not 1 <= marker['threshold_percent'] <= 99
            or set(proof) != {'scope', 'capture', 'tenant_id', 'source_requests'}
            or proof['scope'] != scope or proof['capture'] != capture or proof['tenant_id'] != tenant
            or proof['source_requests'] != marker['source_requests']):
        raise ValueError()
    summary = marker['summary']
    if (not isinstance(summary, dict) or set(summary) != {'callers', 'maximum_operations', 'first_seen', 'last_seen'}
            or type(summary['callers']) is not int or not 1 <= summary['callers'] <= source.MAX_CALLERS
            or type(summary['maximum_operations']) is not int or not 1 <= summary['maximum_operations'] <= marker['operation_count']
            or not source.instant(marker['window_start']) <= source.instant(summary['first_seen']) <= source.instant(summary['last_seen']) < source.instant(marker['window_end'])):
        raise ValueError()
    refs = marker['source_requests']; ledger = metadata[source.KIND + '_receipts']
    if (not isinstance(refs, list) or len(refs) != 4 or len(set(refs)) != 4
            or not isinstance(ledger, list) or not 4 <= len(ledger) <= source.MAX_CALLS
            or len({r['id'] for r in ledger}) != len(ledger)
            or sum(r['bytes'] for r in ledger) > source.MAX_TOTAL):
        raise ValueError()
    for ref, operation in zip(refs, ('subscription', 'apim', 'workspace', 'query')):
        receipt, = [r for r in ledger if r['id'] == ref]
        query = operation == 'query'
        if (set(receipt) != {'id', 'identity', 'scope', 'profile', 'operation', 'method', 'host', 'audience',
                'request_digest', 'capture', 'status', 'bytes', 'tenant_id', 'identity_bound', 'target_binding'}
                or not re.fullmatch('log-sample-read-[1-9][0-9]*', ref)
                or receipt['identity'] != ident or receipt['scope'] != scope or receipt['capture'] != capture
                or receipt['profile'] != 'workspace' or receipt['operation'] != operation
                or receipt['method'] != ('POST' if query else 'GET')
                or receipt['host'] != ('api.loganalytics.azure.com' if query else 'management.azure.com')
                or receipt['audience'] != (source.LOGS if query else source.ARM)
                or receipt['status'] != 'collected' or receipt['identity_bound'] is not True
                or receipt['tenant_id'] != tenant or type(receipt['bytes']) is not int
                or not 1 <= receipt['bytes'] <= source.MAX_WIRE or not re.fullmatch('[0-9a-f]{64}', receipt['request_digest'])
                or query and not re.fullmatch('[0-9a-f]{64}', receipt['target_binding'])
                or not query and receipt['target_binding'] is not None):
            raise ValueError()
    return marker


def evaluate(item, index):
    try:
        marker = bound(item, index)
        summary = marker['summary']
        exceeded = summary['maximum_operations'] * 100 > marker['threshold_percent'] * marker['operation_count']
        text = ('The maximum observed caller operation breadth exceeded the selected threshold.' if exceeded
                else 'The maximum observed caller operation breadth stayed within the selected threshold.')
        return ('FAIL' if exceeded else 'PASS'), {'observed': text + ' This covers matching visible ingested records in one selected hour and does not establish compromise or alert delivery.',
            'window_start': marker['window_start'], 'window_end': marker['window_end'],
            'maximum_operations': summary['maximum_operations'], 'selected_operations': marker['operation_count'],
            'threshold_percent': marker['threshold_percent'], 'observed_callers': summary['callers'],
            'coverage': 'selected_ingested_apim_operation_window'}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError, OverflowError):
        return 'UNKNOWN', {'observed': 'The selected APIM operation window could not be established. Missing, partial or unavailable logs do not establish a negative anomaly result.',
            'coverage': 'incomplete_selected_apim_operation_window'}


PROPOSAL = {'id': source.CHECK, 'provider': 'azure', 'category': 'hardening', 'kind': source.KIND,
    'admission_recommended': False, 'research_only': True,
    'severity': 'medium', 'finding_type': 'monitoring', 'group': 'Monitoring & alerts', 'requirements': [],
    'title': 'Selected APIM observed caller operation breadth stays within the selected threshold',
    'dependencies': [source.KIND],
    'description': 'Compares the maximum caller operation breadth in matching visible ingested records from one selected APIM/workspace and fixed hour against an explicit threshold. Operation IDs are caller-selected APIM identifiers; this is neither compromise detection nor an alert-delivery test.',
    'remediation': ['Review the selected APIM operation IDs, threshold and matching traffic with the service owner.',
                    'Investigate unexpected operation breadth using separately authorized monitoring tools.'],
    'evaluate': evaluate}
