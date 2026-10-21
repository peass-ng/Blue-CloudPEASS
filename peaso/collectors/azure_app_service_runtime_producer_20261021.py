"""Proposed named-check Azure producer; integrate only in the grouped source epoch.

Called after native app_service inventory has been read and before snapshot sealing.
It reuses the existing reader and authenticated ARM request closure. It never
accepts arbitrary site IDs from an option or creates a new inventory.
"""
from peaso.checks import azure_app_service_runtime_native_20261021 as native

CHECK = 'azure.review.app_service.runtime_support_declared'
MARKER = 'runtime_support_native'


def _unknown(reason):
    return {'schema': native.SCHEMA, 'check_id': CHECK, 'status': 'UNKNOWN',
            'complete': False, 'reason': reason, 'source_requests': []}


def collect_selected(reader, request, scopes, collections):
    if not isinstance(scopes, list) or type(collections) is not list:
        raise ValueError('native Azure inventory context required')
    selected = {scope.casefold() for scope in scopes if type(scope) is str}
    for envelope in collections:
        if not isinstance(envelope, dict) or envelope.get('type') != 'app_service':
            continue
        scope = envelope.get('scope')
        if type(scope) is not str or scope.casefold() not in selected:
            continue
        if envelope.get('status') not in ('collected', 'partial'):
            continue
        items = envelope.get('items')
        if type(items) is not list:
            continue
        for item in items:
            if type(item) is not dict:
                continue
            site_id = item.get('id')
            kind = item.get('kind')
            props = item.get('properties')
            # The ordinary inventory must already prove an exact native Linux
            # web app; anything unresolved stays UNKNOWN without new reads.
            if (type(site_id) is not str or native.bounds.SITE_RE.fullmatch(site_id) is None or
                    type(kind) is not str or 'app' not in {x.strip().casefold() for x in kind.split(',')} or
                    'functionapp' in kind.casefold() or 'container' in kind.casefold() or
                    type(props) is not dict or props.get('reserved') is not True):
                item[MARKER] = _unknown('selected Linux web app eligibility unresolved')
                continue
            item[MARKER] = native.collect(reader, request, site_id=site_id,
                                          scope=scope, selected=True)
