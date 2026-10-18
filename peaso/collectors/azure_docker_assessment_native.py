"""Read exact Docker Defender assessment metadata without creating scan facts."""
from __future__ import annotations
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import re

ARM = 'https://management.azure.com'
KEY = '0677209d-e675-2c6f-e91a-54cef2878663'
VERSION = '2020-01-01'
POLICY = '/providers/Microsoft.Authorization/policyDefinitions/e8cbc669-f12d-49eb-93e7-9273119e9933'
_VM = re.compile(r'/subscriptions/[^/?#\\\s]+/resourceGroups/[^/?#\\\s]+/providers/Microsoft\.Compute/virtualMachines/[^/?#\\\s]+', re.I)


def _field(obj, key, typ):
    if not isinstance(obj, dict):
        raise ValueError('native assessment object malformed')
    coverage = obj.get('_coverage', {})
    if not isinstance(coverage, dict):
        raise ValueError('native field coverage malformed')
    if key in coverage and (not isinstance(coverage[key], dict) or coverage[key].get('status') != 'collected'):
        raise ValueError('native assessment field unavailable')
    value = obj.get(key)
    if not isinstance(value, typ):
        raise ValueError('native assessment field absent or malformed')
    return value


def _identity(row, scope):
    rid, name = _field(row, 'id', str), _field(row, 'name', str)
    if name.casefold() != KEY or _field(row, 'type', str).casefold() != 'microsoft.security/assessments':
        raise ValueError('not selected Docker assessment')
    props = _field(row, 'properties', dict)
    resource = _field(props, 'resourceDetails', dict)
    vm = _field(resource, 'id', str)
    if (_field(resource, 'source', str) != 'Azure' or not _VM.fullmatch(vm) or '%' in vm or any(part in ('.', '..') for part in vm.split('/'))
            or not vm.casefold().startswith(scope.casefold() + '/')
            or rid.casefold() != (vm + '/providers/Microsoft.Security/assessments/' + KEY).casefold()):
        raise ValueError('native Docker assessment parent differs')
    return rid, vm


def collect(reader, request, scopes, wanted, credential_context_id, customer_context_id):
    """GET metadata only for already-enumerated, current known-VM Docker rows.

    GET freshness records a provider read, not a new guest scan. No empty
    inventory, applicability, rule completeness, or remediation fact is added.
    """
    if not {'security_assessment', 'vm'} <= set(wanted):
        return
    selected = {s.casefold() for s in scopes}
    vms = {str(row.get('id', '')).casefold() for source in reader.collections
           if source.get('type') == 'vm' and str(source.get('scope', '')).casefold() in selected
           and source.get('status') == 'collected' for row in source.get('items', []) if isinstance(row, dict)}
    jobs = []
    for source in reader.collections:
        scope = source.get('scope', '')
        if (source.get('type') != 'security_assessment' or not isinstance(scope, str)
                or scope.casefold() not in selected or source.get('status') != 'collected'):
            continue
        for position, original in enumerate(source.get('items', [])):
            try:
                rid, vm = _identity(original, scope)
            except (ValueError, TypeError):
                continue
            if vm.casefold() not in vms:
                continue
            jobs.append((source, position, scope, original))
    # Share the existing reader budget/concurrency; reduce in source order.
    def fetch(job):
        return _enrich(reader, request, job[2], job[3], credential_context_id, customer_context_id)
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        for job, enriched in zip(jobs, pool.map(fetch, jobs)):
            job[0]['items'][job[1]] = enriched


def _enrich(reader, request, scope, original, credential_context_id, customer_context_id):
    rid, vm = _identity(original, scope)
    row = deepcopy(original)
    try:
        detail = reader.call(request, ARM + rid + '?api-version=' + VERSION + '&$expand=metadata')
        if _identity(detail, scope) != (rid, vm):
            # ARM identity casing alone is immaterial.
            actual = _identity(detail, scope)
            if tuple(s.casefold() for s in actual) != (rid.casefold(), vm.casefold()):
                raise ValueError('assessment GET returned another resource')
        props = _field(detail, 'properties', dict)
        status = _field(props, 'status', dict)
        code = _field(status, 'code', str)
        if code not in ('Healthy', 'Unhealthy', 'NotApplicable'):
            raise ValueError('unknown native assessment status')
        metadata = _field(props, 'metadata', dict)
        observed = datetime.now(timezone.utc).isoformat()
        projection = {'assessmentType': _field(metadata, 'assessmentType', str),
                      'policyDefinitionId': _field(metadata, 'policyDefinitionId', str)}
        row['properties']['status'] = {'code': code}
        row['properties']['metadata'] = projection
        row['properties'].setdefault('_coverage', {}).pop('metadata', None)
        row['_provenance'] = {'source_operation': 'Assessments_Get', 'read_only': True,
            'observed_at': observed, 'api_version': VERSION, 'representation': 'metadata',
            'metadata_expanded': True, 'scope': scope,
            'credential_context_id': credential_context_id, 'customer_context_id': customer_context_id}
    except Exception as exc:
        # Never reuse an old/caller-supplied metadata field after an
        # unsuccessful native GET. Existing LIST health remains a fact.
        row['properties'].pop('metadata', None)
        failure = {'status': 'not_collected', 'reason': 'native_assessment_metadata_get_unavailable'}
        code = getattr(exc, 'code', None)
        if code in ('call_limit', 'resource_limit', 'page_limit', 'deadline_exceeded',
                    'collection_cancelled', 'retry_after_exceeds_budget'):
            failure['error'] = {'code': code}
        row['properties'].setdefault('_coverage', {})['metadata'] = failure
        origin = original.get('_provenance', {})
        bound_list = (isinstance(origin, dict) and origin.get('source_operation') == 'Assessments_List'
            and origin.get('read_only') is True and origin.get('api_version') == VERSION
            and origin.get('representation') == 'metadata' and isinstance(origin.get('observed_at'), str)
            and isinstance(origin.get('scope'), str) and origin['scope'].casefold() == scope.casefold()
            and origin.get('credential_context_id') == credential_context_id
            and origin.get('customer_context_id') == customer_context_id)
        if not bound_list:
            row.pop('_provenance', None)
        # A failed metadata GET neither erases a genuine LIST observation nor
        # refreshes its read time. It never becomes an expanded-GET witness.
    return row
