"""Bounded read-only Cloud Monitoring queries keyed by public credential IDs."""
from copy import deepcopy
from datetime import timedelta

from peaso.gcp_iam_usage_contract import timestamp
from peaso.gcp_key_usage_contract import API, HMAC, PARENTS, MAX_POINTS, WINDOW_DAYS, LAG, credential_id, parameters


def collect(collector):
    from .gcp import ReadError
    selected = [scope for scope in collector.scopes if scope.startswith('projects/')]
    end = timestamp(collector.read_time)-LAG
    start = end-timedelta(days=WINDOW_DAYS)
    for kind, parent in PARENTS.items():
        if kind not in collector.needed:
            continue
        for owner in selected:
            def rows(owner=owner, kind=kind, parent=parent):
                inventory = collector.collections.get((parent, owner))
                if not inventory or inventory.get('status') not in ('collected', 'empty', 'partial'):
                    raise ReadError('unavailable', 'credential_inventory_unavailable')
                def individual(item):
                    try:
                        ident = credential_id(item, kind)
                    except ValueError:
                        return None  # The current credential itself remains UNKNOWN.
                    # Deleted/inactive identities have explicit applicability.
                    if (kind == API and item.get('deleteTime')) or (kind == HMAC and item.get('state') in ('INACTIVE', 'DELETED')):
                        return None
                    current_name = item.get('name') if kind == API else item.get('accessId')
                    record = {'name': owner+'/'+kind+'/'+ident, 'credential_id': ident,
                        'credential_name': current_name, 'owner_scope': owner,
                        'observation_start': start.isoformat(), 'observation_end': end.isoformat(),
                        'selected_project_scopes': list(selected), 'views': []}
                    refs, points = [], 0
                    for scope in ([owner] if kind == API else selected):
                        view = {'scope': scope, 'status': 'collected', 'source_requests': [], 'series': []}
                        try:
                            binding = collector._data_project_binding(scope, require_alias=True)
                            view['project_id'] = binding['project_id']
                            view['project_number'] = binding['project_number']
                            query = parameters(kind, binding['project_id'], ident, start.isoformat(), end.isoformat())
                            view['query'] = deepcopy(query)
                            def complete_response(data):
                                if data.get('executionErrors'):
                                    raise ReadError('unavailable', 'partial_metric_execution')
                            for page, ref in collector.pages(f'https://monitoring.googleapis.com/v3/{scope}/timeSeries', scope,
                                    key='timeSeries', params=query, response_validator=complete_response):
                                refs.append(ref)
                                view['source_requests'].append(ref)
                                for series in page:
                                    native_points = series.get('points')
                                    if not isinstance(native_points, list):
                                        raise ReadError('malformed', 'metric_points_unavailable')
                                    points += len(native_points)
                                    if points > MAX_POINTS:
                                        raise ReadError('unavailable', 'credential_metric_point_limit')
                                    view['series'].append(deepcopy(series))
                        except ReadError as exc:
                            if scope == owner and 'query' not in view:
                                item.setdefault('_coverage', {})['_usageProjectIdentity'] = {'status': exc.status, 'error': exc.error}
                            view.update(status=exc.status, error=exc.error)
                            if getattr(exc, 'request_id', None):
                                refs.append(exc.request_id)
                                view['source_requests'].append(exc.request_id)
                        record['views'].append(view)
                    # A before-HTTP failure retains parent identity provenance,
                    # without asserting that any successful metric query occurred.
                    record['metric_source_requests'] = list(dict.fromkeys(refs))
                    ref = refs[-1] if refs else item['_provenance']['source_requests'][0]
                    return record, ref
                for result in collector.parallel(individual, inventory['items']):
                    if result is not None:
                        record, ref = result
                        yield [record], ref
            collector.add(kind, owner, 'monitoring', rows)
