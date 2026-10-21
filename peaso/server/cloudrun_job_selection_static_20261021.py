"""API-only Cloud Run Job selectors, equal to native preflight.

This validates input shape; it does not authorize reads or attest an image.
"""
from copy import deepcopy
import re
from . import cloudrun_image_grammar_static_20261021 as association

MAX_SELECTIONS = 4

def _require(value, reason):
    if not value:
        raise ValueError(reason)

def normalize_selection(selectors, scope):
    """Closed selectors; validate everything before sessions or credentials."""
    _require(type(scope) is str and scope.startswith('projects/'), 'exact_project_required')
    project = scope.removeprefix('projects/')
    _require(association._PROJECT.fullmatch(project), 'exact_project_id_required')
    _require(type(selectors) is list and 1 <= len(selectors) <= MAX_SELECTIONS,
             'bounded_explicit_selectors_required')
    identities, uids = set(), {}
    for item in selectors:
        _require(type(item) is dict and set(item) == association._SELECTOR_KEYS,
                 'closed_selector_required')
        _require(item['api_version'] == association.RUN_API and item['kind'] == 'Job'
                 and item['project_id'] == project, 'only_selected_project_v2_job_supported')
        name, uid, container = (item[k] for k in ('resource_name', 'resource_uid', 'container_name'))
        _require(type(name) is str and len(name) <= 512 and re.fullmatch(
            re.escape(scope) + r'/locations/[a-z][a-z0-9-]{0,62}/jobs/' + association._RESOURCE_ID,
            name), 'exact_job_name_required')
        _require(type(uid) is str and association._UUID.fullmatch(uid), 'exact_job_uuid_required')
        _require(type(container) is str and association._LABEL.fullmatch(container),
                 'exact_container_name_required')
        parsed = association._immutable(item['immutable_reference'])
        _require(parsed['project_id'] == project and item['repository'] == parsed['repository']
                 and item['digest'] == parsed['digest'], 'selector_image_scope_mismatch')
        key = name, container
        _require(key not in identities and uids.get(name, uid) == uid,
                 'duplicate_or_ambiguous_job_selection')
        identities.add(key)
        uids[name] = uid
    return deepcopy(selectors)

from types import SimpleNamespace as _Namespace
source = _Namespace(normalize_selection=normalize_selection)
OPTION = "selected_cloudrun_job_declared_images"

def validate_options(options, scopes):
    """Closed bounded exact selectors, including when content reads are disabled."""
    if 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
        raise ValueError('content_secret_scans must be a boolean')
    if OPTION not in options:
        return []
    if (not isinstance(scopes, list) or len(scopes) != 1 or
            any(options.get(key) for key in ('all_projects', 'discover_projects', 'all_hierarchy'))):
        raise ValueError('Job image inspection requires one exact project without discovery')
    return source.normalize_selection(options[OPTION], scopes[0])


def validate_image_options(provider, options, scopes):
    """Validate the independent opt-in; never issue native read authorization."""
    if 'image_vulnerability_scans' not in options:
        return
    if provider != 'gcp' or type(options['image_vulnerability_scans']) is not bool:
        raise ValueError('image_vulnerability_scans requires a GCP boolean')
    targets = validate_options(options, scopes)
    if options['image_vulnerability_scans'] is True and not targets:
        raise ValueError('Enabled image vulnerability scans require exact Job image selectors')
