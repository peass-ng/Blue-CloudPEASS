"""Read-only unfiltered Entra assignment/PIM receipts, with shared reader budgets."""
from datetime import datetime, timezone
from peaso.azure_unused_role_contract import KIND, SCHEMA, REPORTS, GRAPH, MAX_ROWS, project, guid, validate_read


def collect(reader, request, scopes, wanted, transport, credential_context_id, customer_context_id):
    if KIND not in wanted: return
    from .azure import _safe_error, AzureReadError
    try:
        tenant = guid(getattr(transport, 'verified_tenant', None))
        if guid(getattr(transport, 'tenant', None)) != tenant:
            raise ValueError('selected directory differs from authenticated tenant')
    except ValueError as exc:
        reader.unavailable(KIND, '/tenants/unverified', 'Microsoft.Graph', exc)
        return
    scope = '/tenants/'+tenant
    proof = {'schema': SCHEMA, 'endpoint': 'native-unused-role-projection', 'read_only': True,
        'tenant_id': tenant, 'tenant_verified': True, 'credential_context_id': credential_context_id,
        'customer_context_id': customer_context_id, 'observed_at': datetime.now(timezone.utc).isoformat()}
    reports = []
    for name, endpoint in REPORTS.items():
        source = {'name': name, 'endpoint': endpoint, 'audience': GRAPH, 'method': 'GET', 'body': None,
            'filter': None, 'projection': 'full', 'items': [], 'status': 'not_collected', 'integrity_error': False}
        seen = set()
        try:
            def read(url, *, audience=GRAPH, body=None):
                validate_read(url, endpoint, audience=audience, body=body)
                return request(url, audience=audience, body=body)
            for page in reader.pages(read, GRAPH+endpoint, audience=GRAPH, next_key='@odata.nextLink'):
                if not isinstance(page, list): raise ValueError('native role consumer page is malformed')
                for raw in page:
                    row = project(raw)
                    if row['id'] in seen: raise ValueError('native role consumer identity is duplicated')
                    if len(source['items']) >= MAX_ROWS: raise AzureReadError('resource_limit')
                    if reader.budget.max_items is not None and len(source['items']) >= reader.budget.max_items:
                        raise AzureReadError('resource_limit')
                    seen.add(row['id']);source['items'].append(row)
            source['status'] = 'collected' if source['items'] else 'empty'
        except Exception as exc:
            status, error = _safe_error(exc)
            source.update(status='partial' if source['items'] else status, error={**error, 'cause_status': status}, integrity_error=isinstance(exc, ValueError))
        reports.append(source)
    record = {'id': scope+'/unusedRoleEvidence', 'schema': SCHEMA, 'reports': reports, '_provenance': proof}
    reader.collections.append({'type': KIND, 'scope': scope, 'service': 'Microsoft.Graph',
        'status': 'collected', 'items': [record], '_provenance': dict(proof)})
