"""Collect names and fingerprints of existing Deployment Manager deployments."""

from __future__ import annotations

import re


def project(item):
    if not isinstance(item, dict):
        raise ValueError('deployment_manager_deployment_not_object')
    name = item.get('name')
    if not isinstance(name, str) or not re.fullmatch(r'[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?', name):
        raise ValueError('deployment_manager_name_invalid')
    fingerprint = item.get('fingerprint')
    if fingerprint is not None and (not isinstance(fingerprint, str) or not fingerprint):
        raise ValueError('deployment_manager_fingerprint_invalid')
    return {'name': name, **({'fingerprint': fingerprint} if fingerprint else {})}


def collection_pages(collector, scope):
    def checked(item):
        try:
            return project(item)
        except ValueError as exc:
            from .gcp import ReadError
            raise ReadError('malformed', str(exc)) from exc

    base = f'https://www.googleapis.com/deploymentmanager/v2/{scope}/global/deployments'
    for rows, request_id in collector.pages(
            base, scope, key='deployments', page_size_key='maxResults',
            params={'fields': 'deployments(name,fingerprint),nextPageToken'},
            transform=checked):
        def hydrate(row):
            return collector.hydrate(row, 'iamPolicy',
                                     base + '/' + row['name'] + '/getIamPolicy', scope)
        yield collector.parallel(hydrate, rows), request_id
