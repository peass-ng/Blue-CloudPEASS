"""Pure selected App Engine Flex version and immutable image validator."""
from copy import deepcopy
import re

OPTION = 'selected_appengine_flex_version_images'
SECRET_CHECK = 'gcp.review.app_engine_flex.selected_version_image_secret_indicators'
VULN_CHECK = 'gcp.review.app_engine_flex.selected_version_image_high_vulnerabilities'
SECRET_KIND = 'appengine_flex_selected_version_image_secrets'
VULN_KIND = 'appengine_flex_selected_version_image_vulnerabilities'
ENABLE_SECRET = 'content_secret_scans'
ENABLE_VULN = 'image_vulnerability_scans'
VERSION = re.compile(r'apps/([a-z][a-z0-9-]{4,28}[a-z0-9])/services/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)/versions/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\Z')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
AR = re.compile(r'([a-z0-9-]+)-docker\.pkg\.dev/([a-z][a-z0-9-]{4,28}[a-z0-9])/([a-z0-9._-]+)/([a-z0-9._/-]+)@(sha256:[a-f0-9]{64})\Z')
GCR = re.compile(r'(gcr\.io|us\.gcr\.io|eu\.gcr\.io|asia\.gcr\.io)/([a-z][a-z0-9-]{4,28}[a-z0-9])/([a-z0-9._/-]+)@(sha256:[a-f0-9]{64})\Z')
GCR_REPOS = {'gcr.io': ('us', 'gcr.io'), 'us.gcr.io': ('us', 'us.gcr.io'),
             'eu.gcr.io': ('europe', 'eu.gcr.io'), 'asia.gcr.io': ('asia', 'asia.gcr.io')}


def image(value, project):
    if type(value) is not str or len(value) > 512 or value.startswith(('https://', 'http://')):
        raise ValueError('immutable_native_image_required')
    matched = AR.fullmatch(value)
    if matched:
        location, owner, repository, path, digest = matched.groups()
    else:
        matched = GCR.fullmatch(value)
        if not matched:
            raise ValueError('immutable_native_image_required')
        host, owner, path, digest = matched.groups()
        location, repository = GCR_REPOS[host]
    if owner != project or not DIGEST.fullmatch(digest) or any(part in ('', '.', '..') for part in path.split('/')):
        raise ValueError('foreign_or_unsafe_image')
    return f'projects/{owner}/locations/{location}/repositories/{repository}', digest


def selected(options, scopes, named=()):
    if type(options) is not dict or type(scopes) is not list:
        raise ValueError('invalid_flex_selection')
    if any(key in options for key in ('trivy_db_cache', 'trivy_cli')):
        raise ValueError('trivy_runtime_configuration_is_not_a_request_option')
    for flag in (ENABLE_SECRET, ENABLE_VULN):
        if flag in options and type(options[flag]) is not bool:
            raise ValueError('invalid_flex_flag')
    active = (options.get(ENABLE_SECRET) is True and SECRET_CHECK in named
              or options.get(ENABLE_VULN) is True and VULN_CHECK in named)
    if OPTION not in options and not active:
        return []
    rows = options.get(OPTION)
    if type(rows) is not list or not 1 <= len(rows) <= 4 or len(scopes) != 1:
        raise ValueError('exact_flex_selection_required')
    scope = scopes[0]
    if type(scope) is not str or not re.fullmatch(r'projects/[a-z][a-z0-9-]{4,28}[a-z0-9]', scope):
        raise ValueError('exact_project_required')
    project = scope.split('/')[1]
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != {'version_name', 'immutable_reference'}:
            raise ValueError('closed_flex_selection_required')
        name, ref = row['version_name'], row['immutable_reference']
        match = VERSION.fullmatch(name) if type(name) is str and len(name) <= 512 else None
        if not match or match[1] != project or name in seen:
            raise ValueError('foreign_or_duplicate_version')
        image(ref, project)
        seen.add(name)
    return deepcopy(rows)
