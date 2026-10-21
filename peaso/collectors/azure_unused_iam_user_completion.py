"""Read-only Graph user-success receipt for the existing Entra user control."""
from datetime import datetime, timezone
from peaso.azure_unused_iam_contract import guid
from peaso.azure_unused_iam_user_completion_contract import (KIND, SCHEMA, GRAPH, ENDPOINT, SELECT, MAX_ROWS, digest, validate_read, project)

def collect(reader, request, scopes, wanted, transport, credential_context_id, customer_context_id):
    if KIND not in wanted:
        return
    from .azure import _safe_error
    try:
        tenant = guid(getattr(transport, 'verified_tenant', None))
        if guid(getattr(transport, 'tenant', None)) != tenant:
            raise ValueError('selected and verified tenants differ')
    except ValueError as exc:
        reader.unavailable(KIND, '/tenants/unverified', 'Microsoft.Graph', exc)
        return
    scope = '/tenants/' + tenant
    proof = {'schema': SCHEMA, 'endpoint': 'native-user-success-projection', 'read_only': True,
             'tenant_id': tenant, 'tenant_verified': True, 'credential_context_id': credential_context_id,
             'customer_context_id': customer_context_id, 'observed_at': datetime.now(timezone.utc).isoformat()}
    source = {'endpoint': ENDPOINT, 'audience': GRAPH, 'method': 'GET', 'body': None,
              'items': [], 'status': 'not_collected', 'integrity_error': False}
    seen = set()
    try:
        def guarded_request(url, *, audience=GRAPH, body=None):
            validate_read(url, audience=audience, body=body)
            return request(url, audience=audience, body=body)
        for page in reader.pages(guarded_request, GRAPH + ENDPOINT, audience=GRAPH, next_key='@odata.nextLink'):
            for raw in page:
                row = project(raw)
                if row['id'] in seen or len(source['items']) >= MAX_ROWS:
                    raise ValueError('duplicate or excessive Graph user identity')
                seen.add(row['id'])
                source['items'].append(row)
        source['status'] = 'collected' if source['items'] else 'empty'
    except Exception as exc:
        status, error = _safe_error(exc)
        source.update(status='partial' if source['items'] else status, error=error,
                      integrity_error=isinstance(exc, ValueError))
    source['items_sha256'] = digest(source['items'])
    record = {'id': scope + '/userSuccessEvidence', 'schema': SCHEMA, 'source': source,
              '_provenance': proof}
    reader.collections.append({'type': KIND, 'scope': scope, 'service': 'Microsoft.Graph',
                               'status': 'collected', 'items': [record], '_provenance': dict(proof)})


def required_types(wanted):
    return {'directory_user'} if KIND in wanted else set()
