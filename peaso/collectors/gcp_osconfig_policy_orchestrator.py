"""Read exact project, folder, and organization policy orchestrator identities."""

from __future__ import annotations

import re

from .gcp import ReadError


def parents(collector):
    scopes = {scope for scope in collector.scopes
              if re.fullmatch(r'(?:projects/[A-Za-z0-9._:-]+|folders/[1-9][0-9]*|organizations/[1-9][0-9]*)', scope)}
    for kind in ('folder', 'organization'):
        for _, row in collector.items(kind):
            name = row.get('name')
            if isinstance(name, str) and re.fullmatch(
                    r'(?:folders|organizations)/[1-9][0-9]*', name):
                scopes.add(name)
    for _, row in collector.items('project'):
        for ancestor in row.get('_ancestry') or []:
            resource = ancestor.get('resourceId') if isinstance(ancestor, dict) else None
            if isinstance(resource, dict) and resource.get('type') in ('folder', 'organization'):
                ident = str(resource.get('id') or '')
                if re.fullmatch(r'[1-9][0-9]*', ident):
                    scopes.add(resource['type'] + 's/' + ident)
    return sorted(scopes)


def scope_job(collector, parent):
    seen = set()
    prefix = parent + '/locations/global/policyOrchestrators/'

    def keep(row):
        name = row.get('name')
        match = re.fullmatch(r'(projects/[^/]+|folders/[1-9][0-9]*|organizations/[1-9][0-9]*)'
                             r'/locations/global/policyOrchestrators/'
                             r'([a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)', name) if isinstance(name, str) else None
        if not match:
            raise ReadError('malformed', 'osconfig_orchestrator_name_invalid')
        native_parent, ident = match.groups()
        if native_parent != parent:
            if not parent.startswith('projects/') or not native_parent.startswith('projects/'):
                raise ReadError('malformed', 'osconfig_orchestrator_foreign_parent')
            binding = collector._data_project_binding(parent, require_alias=True)
            if native_parent.split('/', 1)[1] not in {binding['project_id'], binding['project_number']}:
                raise ReadError('malformed', 'osconfig_orchestrator_foreign_project')
        canonical = prefix + ident
        if canonical in seen:
            raise ReadError('malformed', 'osconfig_orchestrator_duplicate')
        seen.add(canonical)
        return {'name': canonical}

    return ('osconfig_policy_orchestrator', parent, 'osconfig',
            lambda: collector.pages('https://osconfig.googleapis.com/v2/' + parent +
                                    '/locations/global/policyOrchestrators', parent,
                                    key='policyOrchestrators', transform=keep))


def collect(collector):
    if 'osconfig_policy_orchestrator' in collector.needed:
        collector.run_jobs([scope_job(collector, parent) for parent in parents(collector)])
