"""Unregistered opt-in literal scans; exact shared hooks are review proposals.

All application values are scanned transiently before transport caching. No
execution, message consumption, code download or credential validation occurs.
"""
import base64
import json
import re
import time
from urllib.parse import urlsplit
from peaso.secret_scanning import scan_content, merge_leaks

SCHEMA = 'gcp-additional-literal-secrets-v1'
MARKER = 'AdditionalLiteralSecretIndicators'
SCHEDULER = 'scheduler_job'
APPENGINE = 'app_engine_version_secret'
WORKFLOW = 'workflow_source'
KINDS = (SCHEDULER, APPENGINE, WORKFLOW)
OPERATION = 'additional-literal-secrets:'
PROJECT = r'[a-z][a-z0-9-]{0,62}'
SEGMENT = r'[a-z0-9][a-z0-9-]{0,62}'
SCOPE = re.compile(r'projects/' + PROJECT)
JOB = re.compile(r'projects/(' + PROJECT + r')/locations/(' + SEGMENT + r')/jobs/([A-Za-z0-9_-]{1,500})')
VERSION = re.compile(r'apps/(' + PROJECT + r')/services/(' + SEGMENT + r')/versions/(' + SEGMENT + r')')
FLOW = re.compile(r'projects/(' + PROJECT + r')/locations/(' + SEGMENT + r')/workflows/([A-Za-z][A-Za-z0-9_-]{0,127})')
REVISION = re.compile(r'[0-9]{6}-[a-f0-9]{3}')
APP_PARAMS = {'view': 'FULL', 'fields': 'name,id,envVariables,buildEnvVariables'}
MAX_HTTP_BYTES = 524288
MAX_VALUE_BYTES = 65536
MAX_ROW_BYTES = 262144
MAX_SCOPE_BYTES = 1048576
MAX_PAIRS = 128
MAX_ROWS = 100
MAX_PAGES = 3
MAX_LOCATIONS = 20
MAX_CALLS = 128
MAX_SECONDS = 60
MAX_LEAKS = 256
MAX_LEAK_LOCATIONS = 512


def enabled(options, kind):
    return (options.get('content_secret_scans') is True and
            isinstance(options.get('_content_secret_scan_kinds'), list) and
            kind in options['_content_secret_scan_kinds'])


def prepare_scope(collector, scope):
    """Root calls after scope discovery; content still needs both explicit gates."""
    if not any(kind in collector.needed and enabled(collector.options, kind) for kind in KINDS):
        return
    if not isinstance(scope, str) or not SCOPE.fullmatch(scope) or scope not in collector.scopes:
        return
    with collector.transport.lock:
        if not hasattr(collector.transport, '_additional_scopes'):
            collector.transport._additional_scopes = set()
        for kind in KINDS:
            if kind in collector.needed and enabled(collector.options, kind):
                collector.transport._additional_scopes.add((scope, kind))


def _allowed(transport, scope, kind):
    return enabled(transport.options, kind) and (scope, kind) in getattr(transport, '_additional_scopes', set())


def scheduler_endpoint(url):
    return bool(isinstance(url, str) and re.fullmatch(
        r'https://cloudscheduler\.googleapis\.com/v1/projects/' + PROJECT +
        r'/locations/' + SEGMENT + r'/jobs(?:/[A-Za-z0-9_-]{1,500})?', url))


def should_intercept(transport, method, url, scope):
    # Invalid methods/params still fail in the isolated validator before auth.
    return scheduler_endpoint(url) and _allowed(transport, scope, SCHEDULER)


def _bound(name, scope, kind):
    regex = {SCHEDULER: JOB, APPENGINE: VERSION, WORKFLOW: FLOW}.get(kind)
    match = regex.fullmatch(name) if regex and isinstance(name, str) else None
    return bool(match and 'projects/' + match[1] == scope)


def unavailable(name, scope, kind):
    return {'schema': SCHEMA, 'identity': name, 'scope': scope, 'kind': kind,
            'complete': False, 'surfaces': [], 'leaks': [], 'verification': 'not_attempted', 'revision': None}


def _map(value):
    if not isinstance(value, dict) or len(value) > MAX_PAIRS:
        raise ValueError('map bound')
    for key, val in value.items():
        if not isinstance(key, str) or not key or len(key.encode()) > 256 or not isinstance(val, str) or len(val.encode()) > MAX_VALUE_BYTES:
            raise ValueError('literal pair')
    # Keys are inspected too, but are never used as leak locations.
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def _bytes(value):
    if not isinstance(value, str) or len(value) > 4 * ((MAX_VALUE_BYTES + 2) // 3):
        raise ValueError('base64 bound')
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) > MAX_VALUE_BYTES or base64.b64encode(decoded).decode() != value:
        raise ValueError('canonical base64')
    decoded.decode('utf-8', errors='strict')
    return decoded


def surfaces_for(row, kind):
    if kind == SCHEDULER:
        targets = set(row) & {'httpTarget', 'appEngineHttpTarget', 'pubsubTarget'}
        if len(targets) != 1:
            raise ValueError('target union')
        target_name = next(iter(targets))
        target = row[target_name]
        if not isinstance(target, dict) or any(k in target for k in ('headerNames', 'attributeNames')):
            raise ValueError('unavailable target')
        if target_name == 'httpTarget':
            uri = target.get('uri')
            parsed = urlsplit(uri) if isinstance(uri, str) else None
            if parsed is None or parsed.scheme not in ('http', 'https') or not parsed.hostname:
                raise ValueError('HTTP target')
        if target_name == 'pubsubTarget':
            topic = target.get('topicName')
            owner = row['name'].split('/locations/')[0]
            if not isinstance(topic, str) or not re.fullmatch(re.escape(owner) + r'/topics/[A-Za-z][A-Za-z0-9._~+%-]{2,254}', topic):
                raise ValueError('Pubsub target')
        mapping, content = ('attributes', 'data') if target_name == 'pubsubTarget' else ('headers', 'body')
        values, body = _map(target.get(mapping, {})), _bytes(target.get(content, ''))
        if target_name == 'pubsubTarget' and not body and not target.get(mapping):
            raise ValueError('empty pubsub message')
        return [(target_name + '.' + mapping, values), (target_name + '.' + content, body)]
    if kind == APPENGINE:
        if any(k in row for k in ('environmentVariableNames', 'envVariableNames', 'buildEnvVariableNames')):
            raise ValueError('redacted environment')
        return [(field, _map(row.get(field, {}))) for field in ('envVariables', 'buildEnvVariables')]
    if kind == WORKFLOW:
        value = row.get('sourceContents')
        if not isinstance(value, str) or not value or len(value.encode()) > 131072:
            raise ValueError('missing or oversized source')
        if row.get('state') != 'ACTIVE' or not isinstance(row.get('revisionId'), str) or not REVISION.fullmatch(row['revisionId']):
            raise ValueError('unavailable revision')
        return [('sourceContents', value.encode())]
    raise ValueError('kind')


def scan_row(row, scope, kind, *, expected_name=None, revision=None, budget=None, check_cancelled=lambda: None, _redact_values=None):
    name = row.get('name') if isinstance(row, dict) else None
    marker = unavailable(name if _bound(name, scope, kind) else None, scope, kind)
    budget = [MAX_SCOPE_BYTES, time.monotonic() + MAX_SECONDS] if budget is None else budget
    try:
        if not _bound(name, scope, kind) or (expected_name is not None and name != expected_name):
            raise ValueError('subject')
        if (row.get('collection_status', 'collected') != 'collected' or row.get('_coverage')
                or row.get('_field_mask') or row.get('unreachable')):
            raise ValueError('partial')
        if kind == APPENGINE and row.get('id') != name.rsplit('/', 1)[1]:
            raise ValueError('version id')
        if kind == WORKFLOW and (revision is None or row.get('revisionId') != revision):
            raise ValueError('revision')
        payloads = surfaces_for(row, kind)
        total = sum(len(payload) for _, payload in payloads)
        if total > MAX_ROW_BYTES or total > budget[0]:
            raise ValueError('byte budget')
        budget[0] -= total
        marker['revision'] = revision if kind == WORKFLOW else None
        for surface, payload in payloads:
            check_cancelled()
            remaining = budget[1] - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('scan budget')
            outcome = scan_content(payload, surface, timeout=min(10, remaining / 2), _redact_values=_redact_values)
            marker['surfaces'].append({'surface': surface, 'bytes': len(payload),
                'complete': outcome['complete'], 'engines': outcome['engines']})
            marker['leaks'] = merge_leaks(marker['leaks'] + outcome['leaks'])
            if len(marker['leaks']) > MAX_LEAKS or sum(len(x['locations']) for x in marker['leaks']) > MAX_LEAK_LOCATIONS:
                raise ValueError('result budget')
        check_cancelled()
        marker['complete'] = time.monotonic() < budget[1] and all(s['complete'] is True for s in marker['surfaces'])
    except Exception:
        marker['complete'] = False
    return marker


def scheduler_scrub(job):
    """Match current target metadata/reference scrub; drop free-form error text.

    Existing collector scrub may safely run again: literal targets are gone and
    top-level marker survives. Names-only target metadata is preserved idempotently.
    """
    from .gcp import sanitize
    output = {k: v for k, v in job.items() if k in ('name', 'schedule', 'timeZone', 'userUpdateTime', 'state',
        'scheduleTime', 'lastAttemptTime', 'retryConfig', 'attemptDeadline', 'satisfiesPzs')}
    for field in ('httpTarget', 'pubsubTarget', 'appEngineHttpTarget'):
        target = job.get(field)
        if not isinstance(target, dict):
            continue
        kept = {k: target[k] for k in ('httpMethod', 'topicName', 'relativeUri', 'appEngineRouting', 'oauthToken', 'oidcToken') if k in target}
        if isinstance(target.get('uri'), str):
            parts = urlsplit(target['uri'])
            kept['uri'] = f"{parts.scheme}://{parts.netloc.rsplit('@', 1)[-1]}{parts.path}"
        for mapping in ('headers', 'attributes'):
            if isinstance(target.get(mapping), dict):
                kept[mapping[:-1] + 'Names'] = sorted(target[mapping])
        output[field] = kept
    return sanitize(output)


def strip_provider_markers(data):
    """Root applies to ordinary Scheduler reads too: native markers are untrusted."""
    if isinstance(data, dict):
        rows = data.get('jobs') if 'jobs' in data else [data]
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    row.pop(MARKER, None)
    return data


def finish_scheduler_scrub(scrubbed, projected):
    """Restore safe names-only metadata after the unchanged existing transform."""
    if not isinstance(projected, dict):
        return scrubbed
    for target in ('httpTarget', 'appEngineHttpTarget', 'pubsubTarget'):
        original = projected.get(target)
        if not isinstance(original, dict) or not isinstance(scrubbed.get(target), dict):
            continue
        for field in ('headerNames', 'attributeNames'):
            names = original.get(field)
            if isinstance(names, list) and len(names) <= MAX_PAIRS and all(isinstance(n, str) and len(n.encode()) <= 256 for n in names):
                scrubbed[target][field] = names[:]
    return scrubbed


def scheduler_metadata_response(data):
    """Default-off post-parse/pre-cache hook: never scan or retain target values.

    Reuses the existing URI/auth-reference/name-only policy and strips provider
    markers. Free-form descriptions and target error text are not cached.
    Pagination remains a transient native response protocol for the caller.
    """
    if not isinstance(data, dict):
        return {}
    listing = 'jobs' in data or 'nextPageToken' in data or not data
    rows = data.get('jobs', []) if listing else [data]
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError('scheduler metadata bound')
    safe = [scheduler_scrub(row) for row in rows if isinstance(row, dict)]
    if len(safe) != len(rows):
        raise ValueError('scheduler metadata shape')
    result = {'jobs': safe} if listing else safe[0]
    if listing and 'nextPageToken' in data:
        result['nextPageToken'] = data['nextPageToken']
    return result


def validate_request(transport, method, url, params, body, scope, kind):
    if method != 'GET' or body is not None or not SCOPE.fullmatch(scope or '') or not _allowed(transport, scope, kind):
        raise ValueError('read not authorized')
    params = params or {}
    if not isinstance(params, dict):
        raise ValueError('parameters')
    if kind == SCHEDULER:
        parsed = urlsplit(url)
        match = re.fullmatch('/v1/' + re.escape(scope) + r'/locations/(' + SEGMENT + r')/jobs(?:/([A-Za-z0-9_-]{1,500}))?', parsed.path)
        if not scheduler_endpoint(url) or not match:
            raise ValueError('endpoint')
        if match[2] is None:
            if set(params) - {'pageSize', 'pageToken'} or type(params.get('pageSize')) is not int or not 1 <= params['pageSize'] <= MAX_ROWS:
                raise ValueError('page')
            token = params.get('pageToken')
            if token is not None and (not isinstance(token, str) or not token or len(token.encode()) > 4096):
                raise ValueError('cursor')
        elif params:
            raise ValueError('get mask')
        return match[1], match[2]
    # Producer authorization binds exact names, revision, fields and discovery.
    if kind == APPENGINE:
        name = url.removeprefix('https://appengine.googleapis.com/v1/')
        if (url != 'https://appengine.googleapis.com/v1/' + name or not _bound(name, scope, kind)
                or params != APP_PARAMS):
            raise ValueError('appengine endpoint or mask')
    elif kind == WORKFLOW:
        prefix = 'https://workflows.googleapis.com/v1/'
        path = url.removeprefix(prefix)
        if url != prefix + path:
            raise ValueError('workflow endpoint')
        listing = (path == scope + '/locations' or bool(re.fullmatch(re.escape(scope) + '/locations/' + SEGMENT + '/workflows', path)))
        if listing:
            if (set(params) - {'pageSize', 'pageToken'} or type(params.get('pageSize')) is not int
                    or not 1 <= params['pageSize'] <= (MAX_LOCATIONS if path == scope + '/locations' else MAX_ROWS)):
                raise ValueError('workflow page')
            token = params.get('pageToken')
            if token is not None and (not isinstance(token, str) or not token or len(token.encode()) > 4096):
                raise ValueError('workflow cursor')
        elif (not _bound(path, scope, kind) or set(params) != {'revisionId'}
                or not isinstance(params['revisionId'], str) or not REVISION.fullmatch(params['revisionId'])):
            raise ValueError('workflow revision')
    else:
        raise ValueError('kind')
    key = (scope, kind, url, json.dumps(params, sort_keys=True))
    if key not in getattr(transport, '_additional_reads', set()):
        raise ValueError('unbound dependent read')
    return None, None


def read_projected(transport, method, url, *, params=None, body=None, scope=None, kind=None):
    """Root dispatches before generic transport cache and sensitive-path guards."""
    from .gcp import ReadError
    response, rid = None, None
    status = 'unavailable'
    try:
        location, job_id = validate_request(transport, method, url, params, body, scope, kind)
        transport.check_cancelled()
        with transport.lock:
            if not hasattr(transport, '_additional_budgets'):
                transport._additional_budgets = {}
                transport._additional_calls = {}
                transport._additional_rows = {}
            budget = transport._additional_budgets.setdefault((scope, kind), [MAX_SCOPE_BYTES, time.monotonic() + MAX_SECONDS])
            calls = transport._additional_calls.get((scope, kind), 0)
            if (calls >= (MAX_PAGES if kind == SCHEDULER else MAX_CALLS) or time.monotonic() >= budget[1]
                    or transport.max_calls is not None and transport.calls >= transport.max_calls):
                raise ValueError('request budget')
            transport._additional_calls[(scope, kind)] = calls + 1
            transport.calls += 1
            rid = 'request-' + str(len(transport.evidence) + 1)
            evidence = {'id': rid, 'scope': scope, 'method': method, 'url': url,
                'operation': OPERATION + kind, 'query': {k: v for k, v in (params or {}).items() if k != 'pageToken'}, 'status': 'incomplete'}
            transport.evidence.append(evidence)
        headers = dict(transport.credentials.headers())
        headers['Accept-Encoding'] = 'identity'
        from .gcp import native_header_session
        response = native_header_session(transport).request(method, url, params=params, json=None, headers=headers,
            timeout=min(transport.timeout, max(.01, min(1, budget[1] - time.monotonic()))), allow_redirects=False, stream=True)
        evidence['http_status'] = response.status_code
        if response.status_code != 200:
            status = 'denied' if response.status_code in (401, 403) else 'unavailable'
            evidence['status'] = status
            raise ValueError('HTTP failure')
        hdr = {k.lower(): v for k, v in response.headers.items()}
        if hdr.get('content-encoding', 'identity').strip().lower() != 'identity':
            raise ValueError('encoding')
        length, transfer = hdr.get('content-length'), hdr.get('transfer-encoding')
        if length is not None:
            if transfer is not None or not isinstance(length, str) or not re.fullmatch(r'[0-9]{1,9}', length) or int(length) > MAX_HTTP_BYTES:
                raise ValueError('framing')
            length = int(length)
        elif not isinstance(transfer, str) or transfer.strip().lower() != 'chunked':
            raise ValueError('framing')
        raw = bytearray()
        for chunk in response.iter_content(chunk_size=16384):
            transport.check_cancelled()
            if time.monotonic() >= budget[1] or len(raw) + len(chunk) > MAX_HTTP_BYTES:
                raise ValueError('body bound')
            raw.extend(chunk)
        if length is not None and len(raw) != length:
            raise ValueError('truncated')
        def pairs(items):
            out = {}
            for key, value in items:
                if key in out:
                    raise ValueError('duplicate JSON key')
                out[key] = value
            return out
        data = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
        del raw
        if not isinstance(data, dict):
            raise ValueError('response shape')
        if kind == SCHEDULER:
            listing = job_id is None
            rows = data.get('jobs', []) if listing else [data]
            if (not isinstance(rows, list) or len(rows) > MAX_ROWS or data.get('unreachable')
                    or listing and set(data) - {'jobs', 'nextPageToken'}):
                raise ValueError('incomplete page')
            count = transport._additional_rows.get((scope, kind), 0) + len(rows)
            if count > MAX_ROWS:
                raise ValueError('resource bound')
            transport._additional_rows[(scope, kind)] = count
            safe_rows = []
            for row in rows:
                if not isinstance(row, dict) or not _bound(row.get('name'), scope, kind):
                    raise ValueError('subject')
                match = JOB.fullmatch(row['name'])
                if match[2] != location or job_id is not None and match[3] != job_id:
                    raise ValueError('subject')
                safe = scheduler_scrub(row)
                redactions = set()
                safe[MARKER] = scan_row(row, scope, kind, budget=budget, check_cancelled=transport.check_cancelled,
                                        _redact_values=redactions.update)
                from peaso.secret_scanning import redact_matches
                safe = redact_matches(safe, redactions)
                safe_rows.append(safe)
            result = {'jobs': safe_rows} if listing else safe_rows[0]
            if listing and 'nextPageToken' in data:
                token = data['nextPageToken']
                if not isinstance(token, str) or not token or len(token.encode()) > 4096:
                    raise ValueError('cursor')
                result['nextPageToken'] = token  # Transient pagination protocol; no cache/evidence.
        elif kind == APPENGINE:
            expected = url.removeprefix('https://appengine.googleapis.com/v1/')
            if set(data) - {'name', 'id', 'envVariables', 'buildEnvVariables'}:
                raise ValueError('appengine fields mask not honored')
            marker = scan_row(data, scope, kind, expected_name=expected, budget=budget, check_cancelled=transport.check_cancelled)
            result = {'name': expected, MARKER: marker}
        else:
            result = workflow_projection(data, url, params, scope, budget, transport.check_cancelled)
        del data
        transport.check_cancelled()
        if time.monotonic() >= budget[1]:
            raise ValueError('deadline')
        evidence['status'] = 'collected'
        return result, rid
    except Exception:
        error = ReadError(status, 'additional_literal_read_unavailable')
        if rid is not None:
            error.request_id = rid
        raise error from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass


def _authorize_read(collector, scope, kind, url, params):
    """Only producers can bind an extra read, after native subject validation."""
    from .gcp import ReadError
    if not _allowed(collector.transport, scope, kind):
        raise ReadError('unavailable', 'additional_literal_not_enabled')
    with collector.transport.lock:
        if not hasattr(collector.transport, '_additional_reads'):
            collector.transport._additional_reads = set()
        collector.transport._additional_reads.add((scope, kind, url, json.dumps(params, sort_keys=True)))
    return collector.read(url, scope, params=params, operation=OPERATION + kind)


def workflow_projection(data, url, params, scope, budget, cancelled):
    prefix = 'https://workflows.googleapis.com/v1/'
    if not url.startswith(prefix + scope + '/locations'):
        raise ValueError('workflow endpoint')
    path = url[len(prefix):]
    if path == scope + '/locations':
        if set(data) - {'locations', 'nextPageToken'}:
            raise ValueError('location response')
        rows = data.get('locations', [])
        if not isinstance(rows, list) or len(rows) > MAX_LOCATIONS:
            raise ValueError('location bound')
        result = {'locations': []}
        for row in rows:
            name = row.get('name') if isinstance(row, dict) else None
            if not isinstance(name, str) or not re.fullmatch(re.escape(scope) + '/locations/' + SEGMENT, name):
                raise ValueError('location identity')
            result['locations'].append({'name': name})
    elif path.endswith('/workflows'):
        if set(data) - {'workflows', 'nextPageToken', 'unreachable'} or data.get('unreachable'):
            raise ValueError('workflow response')
        rows = data.get('workflows', [])
        if not isinstance(rows, list) or len(rows) > MAX_ROWS:
            raise ValueError('workflow bound')
        result = {'workflows': []}
        for row in rows:
            if (not isinstance(row, dict) or not _bound(row.get('name'), scope, WORKFLOW)
                    or row['name'].rsplit('/workflows/', 1)[0] != path.removesuffix('/workflows')
                    or not isinstance(row.get('revisionId'), str) or not REVISION.fullmatch(row['revisionId'])):
                raise ValueError('workflow subject')
            result['workflows'].append({'name': row['name'], 'revisionId': row['revisionId']})
    else:
        if not _bound(path, scope, WORKFLOW) or not isinstance(params, dict) or set(params) != {'revisionId'}:
            raise ValueError('workflow get')
        marker = scan_row(data, scope, WORKFLOW, expected_name=path, revision=params['revisionId'], budget=budget, check_cancelled=cancelled)
        return {'name': path, 'revisionId': params['revisionId'], MARKER: marker}
    if 'nextPageToken' in data:
        token = data['nextPageToken']
        if not isinstance(token, str) or not token or len(token.encode()) > 4096:
            raise ValueError('cursor')
        result['nextPageToken'] = token
    return result


def workflow_jobs(collector, scope):
    from .gcp import ReadError
    if WORKFLOW not in collector.needed or not enabled(collector.options, WORKFLOW):
        return []
    prepare_scope(collector, scope)
    def fetch():
        total, locations, seen = 0, [], set()
        def pages(url, key, size):
            token, tokens = None, set()
            for _ in range(MAX_PAGES):
                params = {'pageSize': size}
                if token is not None:
                    params['pageToken'] = token
                data, rid = _authorize_read(collector, scope, WORKFLOW, url, params)
                yield data[key], rid
                token = data.get('nextPageToken')
                if token is None:
                    return
                if token in tokens:
                    raise ReadError('unavailable', 'workflow_pagination_incomplete')
                tokens.add(token)
            raise ReadError('unavailable', 'workflow_page_limit')
        base = 'https://workflows.googleapis.com/v1/' + scope + '/locations'
        for rows, rid in pages(base, 'locations', MAX_LOCATIONS):
            yield [], rid
            for row in rows:
                if row['name'] in locations:
                    raise ReadError('unavailable', 'duplicate_workflow_location')
                locations.append(row['name'])
                if len(locations) > MAX_LOCATIONS:
                    raise ReadError('unavailable', 'workflow_location_limit')
        # Finish discovery before requesting any deployed source.
        summaries = []
        for location in locations:
            for rows, rid in pages('https://workflows.googleapis.com/v1/' + location + '/workflows', 'workflows', MAX_ROWS):
                yield [], rid
                for row in rows:
                    if row['name'] in seen:
                        raise ReadError('unavailable', 'duplicate_workflow')
                    seen.add(row['name'])
                    total += 1
                    if total > MAX_ROWS:
                        raise ReadError('unavailable', 'workflow_resource_limit')
                    summaries.append(row)
        for row in summaries:
            data, rid = _authorize_read(collector, scope, WORKFLOW,
                'https://workflows.googleapis.com/v1/' + row['name'], {'revisionId': row['revisionId']})
            yield [data], rid
    return [(WORKFLOW, scope, 'workflows', fetch)]


def appengine_jobs(collector):
    from .gcp import ReadError
    if APPENGINE not in collector.needed or not enabled(collector.options, APPENGINE):
        return []
    jobs = []
    for scope in collector.scopes:
        if not SCOPE.fullmatch(scope):
            continue
        prepare_scope(collector, scope)
        def fetch(scope=scope):
            from .gcp_appengine_versions import VERSIONS_FIELDS
            source = collector.collections.get(('app_engine_version', scope))
            if (not source or source.get('status') not in ('collected', 'empty')
                    or source.get('coverage_status') not in ('collected', 'empty')
                    or not isinstance(source.get('items'), list) or len(source['items']) > MAX_ROWS):
                raise ReadError('unavailable', 'appengine_version_inventory_incomplete')
            seen = set()
            for row in source['items']:
                name = row.get('name') if isinstance(row, dict) else None
                if (not _bound(name, scope, APPENGINE) or name in seen or row.get('_field_mask') != VERSIONS_FIELDS
                        or row.get('id') != name.rsplit('/', 1)[1]):
                    raise ReadError('unavailable', 'appengine_version_subject_unproven')
                seen.add(name)
            for row in source['items']:
                data, rid = _authorize_read(collector, scope, APPENGINE,
                    'https://appengine.googleapis.com/v1/' + row['name'], dict(APP_PARAMS))
                yield [data], rid
        jobs.append((APPENGINE, scope, 'appengine', fetch))
    return jobs
