"""Pure connector-save validation for selected Dataproc source targets.

This mirrors the native reader's finite selector contract and imports no collector,
engine, cloud SDK, credential handler or network client.
"""
from copy import deepcopy
import json
import re

OPTION = 'selected_dataproc_referenced_sources'
KINDS = {'job': 'dataproc_selected_job_source', 'cluster': 'dataproc_selected_initialization_source'}
MAX_TARGETS = 4
SCOPE = re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])\Z')
JOB_FIELDS = {'pysparkJob.mainPythonFileUri': '.py', 'sparkRJob.mainRFileUri': '.R',
              'hiveJob.queryFileUri': None, 'pigJob.queryFileUri': None,
              'sparkSqlJob.queryFileUri': None}
PYSPARK_DEPENDENCY = re.compile(r'pysparkJob\.pythonFileUris\[(0|[1-9][0-9]?)\]\Z')
_BUCKET = re.compile(r'[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\Z')
_DECIMAL = re.compile(r'[1-9][0-9]{0,19}\Z')


def parse(target):
    if not isinstance(target, dict) or set(target) != {'profile', 'resource', 'field', 'bucket', 'object', 'generation'}:
        raise ValueError('invalid_selection')
    profile = target['profile']
    if not isinstance(profile, str) or profile not in KINDS:
        raise ValueError('invalid_selection')
    resource = target['resource']
    tail = r'jobs/[A-Za-z0-9_-]{1,100}' if profile == 'job' else r'clusters/[a-z](?:[a-z0-9-]{0,49}[a-z0-9])?'
    match = re.fullmatch(r'(projects/[a-z][a-z0-9-]{4,28}[a-z0-9])/regions/[a-z][a-z0-9-]{0,62}/' + tail,
                         resource) if isinstance(resource, str) else None
    field = target['field']
    if match is None or not isinstance(field, str) or ((field not in JOB_FIELDS and PYSPARK_DEPENDENCY.fullmatch(field) is None) if profile == 'job' else
            re.fullmatch(r'config.initializationActions\[(0|[1-9][0-9]?)\].executableFile', field) is None):
        raise ValueError('invalid_selection')
    bucket, name, generation = (target[k] for k in ('bucket', 'object', 'generation'))
    try:
        name_size = len(name.encode('utf-8')) if isinstance(name, str) else 0
    except UnicodeError:
        raise ValueError('invalid_selection') from None
    if (not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket)
            or any(len(p) > 63 for p in bucket.split('.')) or not isinstance(name, str)
            or not 1 <= name_size <= 1024 or name.endswith('/')
            or any(c in name for c in '%?#\\') or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(p in ('', '.', '..') for p in name.split('/'))
            or not isinstance(generation, str) or not _DECIMAL.fullmatch(generation)
            or int(generation) > 9223372036854775807):
        raise ValueError('invalid_selection')
    suffixes = ('.py', '.zip', '.egg') if PYSPARK_DEPENDENCY.fullmatch(field) else (JOB_FIELDS.get(field),)
    if suffixes != (None,) and not name.endswith(suffixes):
        raise ValueError('invalid_selection')
    return match[1]


def selected_targets(options, scopes):
    if not isinstance(options, dict) or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
        raise ValueError('invalid_selection')
    kinds = options.get('_content_secret_scan_kinds')
    active = options.get('content_secret_scans') is True and isinstance(kinds, list) and any(k in kinds for k in KINDS.values())
    if OPTION not in options and not active:
        return []
    rows = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
            or len(set(scopes)) != len(scopes) or not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TARGETS):
        raise ValueError('invalid_selection')
    seen = set()
    for row in rows:
        scope = parse(row)
        key = KINDS[row['profile']] + ':' + json.dumps(row, sort_keys=True, separators=(',', ':'))
        if scope not in scopes or key in seen:
            raise ValueError('invalid_selection')
        seen.add(key)
    return deepcopy(rows)
