"""Read exact Developer Connect links referenced by Cloud Build triggers."""

from __future__ import annotations

import re


_LINK = re.compile(r'projects/[^/]+/locations/[^/]+/connections/[^/]+/gitRepositoryLinks/[^/]+')


def collection_pages(collector, scope):
    from .gcp import ReadError
    from .gcp_history import cloudbuild_locations
    locations = []
    for found, request_id in cloudbuild_locations(collector, scope):
        locations.extend(found)
        if request_id:
            yield [], request_id
    seen = set()
    for location in dict.fromkeys(locations):
        for triggers, request_id in collector.pages(
                f'https://cloudbuild.googleapis.com/v1/{scope}/locations/{location}/triggers',
                scope, key='triggers'):
            if request_id:
                yield [], request_id
            for trigger in triggers:
                event = trigger.get('developerConnectEventConfig')
                link = event.get('gitRepositoryLink') if isinstance(event, dict) else None
                if not isinstance(link, str) or not _LINK.fullmatch(link) or link in seen:
                    continue
                seen.add(link)
                link_scope = link.split('/locations/', 1)[0]
                if collector.allowed is not None and link_scope not in collector.allowed:
                    yield [{'name': link, 'linkReadStatus': 'outside_selected_projects',
                            '_representation': 'partial'}], None
                    continue
                try:
                    value, link_request = collector.read(
                        f'https://developerconnect.googleapis.com/v1/{link}', scope)
                except ReadError as exc:
                    yield [{'name': link, 'linkReadStatus': exc.status,
                            '_representation': 'partial'}], getattr(exc, 'request_id', None)
                    continue
                if not isinstance(value, dict) or value.get('name') != link:
                    raise ReadError('malformed', 'developerconnect_link_identity_mismatch')
                proxy = value.get('gitProxyUri')
                if proxy is not None and (not isinstance(proxy, str) or
                                          not proxy.startswith('https://')):
                    raise ReadError('malformed', 'developerconnect_git_proxy_uri_invalid')
                yield [{'name': link,
                        **({'gitProxyUri': proxy} if proxy else {}),
                        'reconciling': value.get('reconciling') is True,
                        '_representation': 'partial'}], link_request
