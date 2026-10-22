"""Collect existing Discovery Engine collection names and IAM policies."""

from __future__ import annotations

import re


_NAME = re.compile(r'projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+')
_STORE = re.compile(r'projects/[^/]+/locations/(?:global|us|eu)/(?:collections/[^/]+/)?dataStores/[^/]+')
_ENGINE = re.compile(r'projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+/engines/[^/]+')


def project(item, scope, location):
    from .gcp import ReadError
    name = item.get('name') if isinstance(item, dict) else None
    if (not isinstance(name, str) or not _NAME.fullmatch(name) or
            not name.startswith(f'{scope}/locations/{location}/')):
        raise ReadError('malformed', 'discoveryengine_collection_identity_invalid')
    return {'name': name, '_representation': 'partial'}


def collection_pages(collector, scope):
    for location in ('global', 'us', 'eu'):
        base = f'https://discoveryengine.googleapis.com/v1alpha/{scope}/locations/{location}/collections'
        for rows, request_id in collector.pages(
                base, scope, key='collections',
                transform=lambda item, loc=location: project(item, scope, loc)):
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
                transform=lambda item, loc=location: project(item, scope, loc)):
            if request_id:
                yield [], request_id
            parents.extend(row['name'] for row in collections)
        for parent in parents:
            base = f'https://discoveryengine.googleapis.com/v1alpha/{parent}/dataStores'
            for stores, request_id in collector.pages(base, scope, key='dataStores'):
                rows = []
                for store in stores:
                    name = store.get('name') if isinstance(store, dict) else None
                    if (not isinstance(name, str) or not _STORE.fullmatch(name)
                            or not name.startswith(location_parent + '/')
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
                transform=lambda item, loc=location: project(item, scope, loc)):
            if request_id:
                yield [], request_id
            for collection in collections:
                parent = collection['name']
                base = f'https://discoveryengine.googleapis.com/v1alpha/{parent}/engines'
                for engines, engine_request in collector.pages(base, scope, key='engines'):
                    rows = []
                    for engine in engines:
                        name = engine.get('name') if isinstance(engine, dict) else None
                        if (not isinstance(name, str) or not _ENGINE.fullmatch(name)
                                or name.rsplit('/engines/', 1)[0] != parent):
                            raise ReadError('malformed', 'discoveryengine_engine_identity_invalid')
                        rows.append({'name': name, '_representation': 'partial'})
                    def hydrate(row):
                        return collector.hydrate(
                            row, 'iamPolicy',
                            f'https://discoveryengine.googleapis.com/v1alpha/{row["name"]}:getIamPolicy',
                            scope)
                    yield collector.parallel(hydrate, rows), engine_request
