"""Pure consumers of actual scoped captures, with envelope provenance closure."""
from copy import deepcopy
from peaso.collectors import gcp_dataflow_batch_source_runtime_20261020 as runtime
from . import gcp_dataflow_referenced_source_request_binding_20261020 as dataflow
from . import gcp_batch_source_row_successor_20261020 as batch

DECLARATIONS = []
for profile, consumer in (('dataflow', dataflow), ('batch', batch)):
    declaration = deepcopy(consumer.DECLARATION)
    declaration.update(ui_group='Secrets', requirements=[], dependencies=[runtime.PROFILES[profile]['kind']],
        remediation='Remove credential literals from the selected referenced source and rotate confirmed exposed credentials. Use supported secret references.')
    DECLARATIONS.append(declaration)


def _unknown():
    return 'UNKNOWN', dict(complete=False, observed='Selected current referenced source was unavailable, unbound or incompletely inspected.')


def _bound(row, profile, scope, capture, envelope):
    try:
        p = runtime.PROFILES[profile]; native = row[p['marker']]
        marker = native if profile == 'dataflow' else native[batch.source.MARKER]
        refs = marker['requests'] if profile == 'dataflow' else marker['source_requests']
        return (row['name'] == marker['identity'] and marker['scope'] == scope and marker['capture'] == capture['capture']
                and row['_provenance'].get('scope') == scope and row['_provenance'].get('capture') == capture['capture']
                and set(row['_provenance'].get('source_requests', [])) == set(refs)
                and row.get('_coverage', {}).get(p['marker']) == {'status': 'collected', 'source_requests': refs}
                and set(refs) <= set(envelope.get('source_requests', [])))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _evaluate(item, index, profile):
    try:
        p = runtime.PROFILES[profile]; ctx = index['context']; scope = ctx['scope']
        if ctx['provider'] != 'gcp':
            return _unknown()
        capture = deepcopy(ctx['metadata'][p['kind'] + '_captures'][scope])
        envelope, = [c for c in index['collections'][p['kind']] if c.get('scope') == scope]
        rows = envelope['items']
        if (envelope['type'] != p['kind'] or envelope['status'] not in ('collected', 'partial')
                or not 1 <= len(rows) <= 4 or len({r['name'] for r in rows}) != len(rows)
                or sum(r == item for r in rows) != 1 or 'items' in capture
                or not _bound(item, profile, scope, capture, envelope)):
            return _unknown()
        # Unwrap the actual rows only; receipts and selection are untouched producer data.
        capture['items'] = [deepcopy(row[p['marker']]) for row in rows]
        native = item[p['marker']]
        status, evidence = (dataflow.evaluate(native, capture) if profile == 'dataflow'
                            else batch.evaluate(native, capture, scope))
        complete = (envelope['status'] == 'collected' and all(_bound(row, profile, scope, capture, envelope) for row in rows))
        if not complete:
            if status == 'PASS':
                return _unknown()
            evidence['complete'] = False
        return status, evidence
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError):
        return _unknown()


def dataflow_source(item, index):
    return _evaluate(item, index, 'dataflow')


def batch_source(item, index):
    return _evaluate(item, index, 'batch')
