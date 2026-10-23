"""Collect existing Discovery Engine collection names and IAM policies."""

from __future__ import annotations

import re


_NAME = re.compile(r'projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+')
_STORE = re.compile(r'projects/[^/]+/locations/(?:global|us|eu)/(?:collections/[^/]+/)?dataStores/[^/]+')
_ENGINE = re.compile(r'projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+/engines/[^/]+')


def _bound_name(collector, name, scope, pattern, code):
    from .gcp import ReadError
    if not isinstance(name, str) or not pattern.fullmatch(name):
        raise ReadError('malformed', code)
    project = name.split('/', 2)[1]
    if project == scope.split('/', 1)[1]:
        return name
    if not project.isdecimal() or collector is None:
        raise ReadError('malformed', code)
    binding = collector._data_project_binding(scope, require_alias=True)
    if project != binding['project_number']:
        raise ReadError('malformed', code)
    return scope + name[len('projects/' + project):]


def project(item, scope, location, collector=None):
    from .gcp import ReadError
    name = _bound_name(collector, item.get('name') if isinstance(item, dict) else None,
                       scope, _NAME, 'discoveryengine_collection_identity_invalid')
    if not name.startswith(f'{scope}/locations/{location}/'):
        raise ReadError('malformed', 'discoveryengine_collection_identity_invalid')
    return {'name': name, '_representation': 'partial'}


def collection_pages(collector, scope):
    for location in ('global', 'us', 'eu'):
        base = f'https://discoveryengine.googleapis.com/v1alpha/{scope}/locations/{location}/collections'
        for rows, request_id in collector.pages(
                base, scope, key='collections',
                transform=lambda item, loc=location: project(item, scope, loc, collector)):
            def hydrate(row):
                return collector.hydrate(
                    row, 'iamPolicy',
                    f'https://discoveryengine.googleapis.com/v1alpha/{row["name"]}:getIamPolicy',
                    scope)
            yield collector.parallel(hydrate, rows), request_id


def data_store_pages(collector, scope):
    from .gcp import ReadError
    seen = set()
    for location in ('global', 'us', 'eu'):
        location_parent = f'{scope}/locations/{location}'
        parents = [location_parent]
        for collections, request_id in collector.pages(
                f'https://discoveryengine.googleapis.com/v1alpha/{location_parent}/collections',
                scope, key='collections',
                transform=lambda item, loc=location: project(item, scope, loc, collector)):
            if request_id:
                yield [], request_id
            parents.extend(row['name'] for row in collections)
        for parent in parents:
            base = f'https://discoveryengine.googleapis.com/v1alpha/{parent}/dataStores'
            for stores, request_id in collector.pages(base, scope, key='dataStores'):
                rows = []
                for store in stores:
                    name = _bound_name(collector, store.get('name') if isinstance(store, dict) else None,
                                       scope, _STORE, 'discoveryengine_data_store_identity_invalid')
                    if (not name.startswith(location_parent + '/')
                            or (parent != location_parent and
                                name.rsplit('/dataStores/', 1)[0] != parent)):
                        raise ReadError('malformed', 'discoveryengine_data_store_identity_invalid')
                    if name in seen:
                        continue
                    seen.add(name)
                    rows.append({'name': name, '_representation': 'partial'})
                def hydrate(row):
                    return collector.hydrate(
                        row, 'iamPolicy',
                        f'https://discoveryengine.googleapis.com/v1alpha/{row["name"]}:getIamPolicy',
                        scope)
                yield collector.parallel(hydrate, rows), request_id


def engine_pages(collector, scope):
    from .gcp import ReadError
    for location in ('global', 'us', 'eu'):
        location_parent = f'{scope}/locations/{location}'
        for collections, request_id in collector.pages(
                f'https://discoveryengine.googleapis.com/v1alpha/{location_parent}/collections',
                scope, key='collections',
                transform=lambda item, loc=location: project(item, scope, loc, collector)):
            if request_id:
                yield [], request_id
            for collection in collections:
                parent = collection['name']
                base = f'https://discoveryengine.googleapis.com/v1alpha/{parent}/engines'
                for engines, engine_request in collector.pages(base, scope, key='engines'):
                    rows = []
                    for engine in engines:
                        name = _bound_name(collector, engine.get('name') if isinstance(engine, dict) else None,
                                           scope, _ENGINE, 'discoveryengine_engine_identity_invalid')
                        if name.rsplit('/engines/', 1)[0] != parent:
                            raise ReadError('malformed', 'discoveryengine_engine_identity_invalid')
                        rows.append({'name': name, '_representation': 'partial'})
                    def hydrate(row):
                        return collector.hydrate(
                            row, 'iamPolicy',
                            f'https://discoveryengine.googleapis.com/v1alpha/{row["name"]}:getIamPolicy',
                            scope)
                    yield collector.parallel(hydrate, rows), engine_request
