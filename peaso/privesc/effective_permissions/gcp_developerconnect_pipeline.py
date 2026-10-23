"""Join one writable Developer Connect link to one repository-driven build trigger."""

from __future__ import annotations

import re

from . import inventory_status, items
from .gcp_bigquery_spark import _new_permission
from .gcp_datafusion_artifact import _rights


_LINK = re.compile(r'projects/[^/]+/locations/[^/]+/connections/[^/]+/gitRepositoryLinks/[^/]+')
_TRIGGER = re.compile(r'projects/[^/]+/locations/[^/]+/triggers/[^/]+')


def _build_identity(model, trigger, project):
    name = model._norm_scope(trigger.get('resourceName') or '')
    if not _TRIGGER.fullmatch(name) or not name.startswith(project + '/locations/'):
        return None
    account = trigger.get('serviceAccount')
    if not account:
        location = name.split('/locations/', 1)[1].split('/', 1)[0]
        account = model.cloudbuild_default_by_location.get((project, location))
    if not isinstance(account, str):
        return None
    email = account.rsplit('/serviceAccounts/', 1)[-1]
    if '@' not in email:
        return None
    return email


def select(model, candidates, source):
    if source is None:
        return {}
    out = {}
    statuses = {model._norm_scope(scope): value for scope, value in
                inventory_status(model.snapshot, 'cloudbuild_trigger').items()}
    links = {model._norm_scope(row.get('name')): row for _, row in
             items(model.snapshot, 'developerconnect_git_repository_link')
             if isinstance(row.get('name'), str)}
    for scope, trigger in items(model.snapshot, 'cloudbuild_trigger'):
        if trigger.get('disabled') is True or trigger.get('eventType') == 'MANUAL':
            continue
        project = model._norm_scope(scope)
        event = trigger.get('developerConnectEventConfig')
        if not isinstance(event, dict):
            continue
        link = model._norm_scope(event.get('gitRepositoryLink') or '')
        if not _LINK.fullmatch(link):
            continue
        identity = _build_identity(model, trigger, project)
        if identity is None:
            continue
        targets = [(tid, target) for tid, target in candidates.items()
                   if target.attrs.get('email') == identity and target.id != source.id]
        if not targets:
            continue
        connection = link.rsplit('/gitRepositoryLinks/', 1)[0]
        location = connection.rsplit('/connections/', 1)[0]
        link_project = link.split('/locations/', 1)[0]
        model.parents.setdefault(link, connection)
        model.parents.setdefault(connection, location)
        model.parents.setdefault(location, link_project)
        token = _rights(model, source, link,
                        ('developerconnect.gitRepositoryLinks.fetchReadWriteToken',))
        proxy = _rights(model, source, link,
                        ('developerconnect.gitRepositoryLinks.gitProxyRead',
                         'developerconnect.gitRepositoryLinks.gitProxyWrite'))
        if token == 'denied' and proxy == 'denied':
            continue
        push = event.get('push')
        source_file = trigger.get('filename')
        git_file = trigger.get('gitFileSource')
        same_repo_file = (isinstance(git_file, dict) and
                          isinstance(git_file.get('path'), str) and bool(git_file['path']) and
                          not git_file.get('uri') and not git_file.get('repository') and
                          not git_file.get('revision'))
        viable = (isinstance(push, dict) and bool(push.get('branch') or push.get('tag'))
                  and ((isinstance(source_file, str) and bool(source_file.strip())) or
                       same_repo_file)
                  and trigger.get('eventType') in (None, 'REPO')
                  and not (trigger.get('approvalConfig') or {}).get('approvalRequired')
                  and not trigger.get('filter')
                  and statuses.get(project) in ('collected', 'empty'))
        link_row = links.get(link)
        link_ready = bool(link_row and link_row.get('reconciling') is False)
        proxy_uri = link_row.get('gitProxyUri') if link_row else None
        proxy_ready = (link_ready and isinstance(proxy_uri, str) and
                       proxy_uri.startswith('https://'))
        for tid, target in targets:
            gain = _new_permission(model, source, target)
            if gain == 'no':
                continue
            if viable and link_ready and gain == 'yes' and (
                    token == 'derived' or proxy == 'derived' and proxy_ready):
                out[tid] = ('conditional', 'exact_developerconnect_link_to_privileged_push_trigger')
            else:
                out.setdefault(tid, ('unknown',
                                     'developerconnect_write_or_trigger_conditions_unresolved'))
    return out
