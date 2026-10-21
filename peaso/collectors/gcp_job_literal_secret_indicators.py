"""Native read-only Dataflow/Batch/Dataproc literal scans; root wiring pending.

Dedicated bounded JSON reads never cache native configuration. Managed secret,
KMS and file/script/image references are not resolved. No jobs are submitted.
"""

from peaso.secret_evidence import scan_with_source
from copy import deepcopy
import hashlib
import http.client
import json
import logging
import math
import re
import threading
import time

from peaso.secret_scanning import scan_content, merge_leaks, redact_matches

SCHEMA = 'gcp-job-literal-secrets-v1'
MARKER = 'JobLiteralSecretIndicators'
IDENTITY = 'JobLiteralIdentity'
DATAFLOW = 'dataflow_job'
BATCH = 'batch_job'
CLUSTER = 'dataproc_cluster'
DATAPROC = 'dataproc_job'
KINDS = (DATAFLOW, BATCH, CLUSTER, DATAPROC)
MAX_HTTP_BYTES = 524288
MAX_WIRE_BYTES = 4194304
MAX_ROW_BYTES = 131072
MAX_SCAN_BYTES = 1048576
MAX_VALUE_BYTES = 16384
MAX_ROWS = 20
MAX_PAGES = 2
MAX_REGIONS = 5
MAX_CALLS = 64
MAX_SECONDS = 60
MAX_LEAKS = 256
MAX_LEAK_LOCATIONS = 512
_PROJECT = re.compile(r'[a-z][a-z0-9-]{0,62}\Z')
_REGION = re.compile(r'[a-z][a-z0-9-]{0,62}\Z')
_ID = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
_UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
_JOB_TYPES = ('hadoopJob', 'sparkJob', 'pysparkJob', 'hiveJob', 'pigJob', 'sparkRJob',
              'sparkSqlJob', 'prestoJob', 'trinoJob', 'flinkJob')


class Incomplete(Exception):
    pass


def enabled(options, kind):
    return options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'), list) and kind in options['_content_secret_scan_kinds']


def regions_for(options, kind):
    key = {DATAFLOW: 'dataflow_regions', BATCH: 'batch_regions', CLUSTER: 'dataproc_regions', DATAPROC: 'dataproc_regions'}[kind]
    regions = options.get(key, options.get('regions'))
    if (not isinstance(regions, list) or not 1 <= len(regions) <= MAX_REGIONS
            or any(not isinstance(r, str) or not _REGION.fullmatch(r) or r == 'global' for r in regions)
            or len(set(regions)) != len(regions)):
        raise Incomplete('explicit_regions_required')
    return regions


def _project(collector, scope):
    rowset = collector.collections.get(('project', scope), {})
    rows = rowset.get('items', [])
    if (rowset.get('coverage_status') != 'collected' or len(rows) != 1 or scope not in collector.scopes
            or scope not in getattr(collector, 'requested_scopes', collector.scopes)):
        raise Incomplete('project_unavailable')
    row = rows[0]
    name, project = row.get('name'), row.get('projectId')
    match = re.fullmatch(r'projects/([1-9][0-9]{0,19})', name) if isinstance(name, str) else None
    if (not match or not isinstance(project, str) or not _PROJECT.fullmatch(project)
            or scope not in ('projects/' + project, name)
            or 'projectNumber' in row and row['projectNumber'] != match[1]):
        raise Incomplete('project_identity_mismatch')
    return project, {project, match[1]}


def _identity(kind, project, region, native_id):
    raw = json.dumps([kind, project, region, native_id], separators=(',', ':')).encode()
    return 'gcp-job-literal:' + hashlib.sha256(raw).hexdigest()


def _native_id(row, kind, region, aliases):
    if not isinstance(row, dict):
        raise Incomplete('row_shape')
    if kind == DATAFLOW:
        if row.get('projectId') not in aliases or row.get('location') != region:
            raise Incomplete('foreign_dataflow')
        ident = row.get('id')
    elif kind == BATCH:
        name = row.get('name')
        match = re.fullmatch(r'projects/([^/]+)/locations/' + re.escape(region) + r'/jobs/([A-Za-z0-9_-]{1,128})', name) if isinstance(name, str) else None
        if not match or match[1] not in aliases or not isinstance(row.get('uid'), str) or not _UUID.fullmatch(row['uid']):
            raise Incomplete('foreign_batch')
        ident = match[2]
    elif kind == CLUSTER:
        if row.get('projectId') not in aliases or not isinstance(row.get('clusterUuid'), str) or not _UUID.fullmatch(row['clusterUuid']):
            raise Incomplete('foreign_cluster')
        ident = row.get('clusterName')
    else:
        reference = row.get('reference')
        if (not isinstance(reference, dict) or reference.get('projectId') not in aliases
                or not isinstance(row.get('jobUuid'), str) or not _UUID.fullmatch(row['jobUuid'])):
            raise Incomplete('foreign_dataproc_job')
        ident = reference.get('jobId')
    if not isinstance(ident, str) or not _ID.fullmatch(ident):
        raise Incomplete('native_id')
    return ident


def _bounded(value, depth=0, count=None):
    count = [0] if count is None else count
    count[0] += 1
    if depth > 8 or count[0] > 2048:
        raise Incomplete('literal_shape_bound')
    if isinstance(value, dict):
        if len(value) > 128 or any(not isinstance(k, str) or len(k.encode()) > 256 for k in value):
            raise Incomplete('literal_map_bound')
        return {k: _bounded(v, depth + 1, count) for k, v in value.items()}
    if isinstance(value, list):
        if len(value) > 128:
            raise Incomplete('literal_array_bound')
        return [_bounded(v, depth + 1, count) for v in value]
    if isinstance(value, str):
        if len(value.encode()) > MAX_VALUE_BYTES:
            raise Incomplete('literal_string_bound')
    elif value is not None and not isinstance(value, (bool, int, float)) or isinstance(value, float) and not math.isfinite(value):
        raise Incomplete('literal_type')
    return value


def _map(value):
    if not isinstance(value, dict) or any(not isinstance(v, str) for v in value.values()):
        raise Incomplete('literal_map')
    return _bounded(value)


def _env(value):
    if not isinstance(value, dict) or set(value) - {'variables', 'secretVariables', 'encryptedVariables'}:
        raise Incomplete('environment_shape')
    if 'secretVariables' in value:
        _map(value['secretVariables'])  # shape only; never scanned or resolved
    if 'encryptedVariables' in value:
        encrypted = value['encryptedVariables']
        if (not isinstance(encrypted, dict) or set(encrypted) != {'keyName', 'cipherText'}
                or any(not isinstance(v, str) or not v or len(v.encode()) > MAX_VALUE_BYTES for v in encrypted.values())):
            raise Incomplete('encrypted_reference_shape')
    # Managed references/ciphertext are never resolved, downloaded or scanned.
    return _map(value.get('variables', {}))


def literals(row, kind):
    if row.get('_coverage') or row.get('_field_mask') or row.get('collection_status', 'collected') != 'collected':
        raise Incomplete('partial_row')
    if kind == DATAFLOW:
        environment = row.get('environment')
        if not isinstance(environment, dict) or row.get('currentState') in (None, 'JOB_STATE_UNKNOWN', 'JOB_STATE_PENDING', 'JOB_STATE_QUEUED'):
            raise Incomplete('dataflow_full_environment_required')
        options = environment.get('sdkPipelineOptions', {})
        if not isinstance(options, dict):
            raise Incomplete('sdk_options_shape')
        pools = environment.get('workerPools', [])
        if not isinstance(pools, list) or len(pools) > 20 or any(not isinstance(p, dict) for p in pools):
            raise Incomplete('worker_pools_shape')
        for pool in pools:
            _map(pool.get('metadata', {}))
        # Environment is returned configuration, including SDK options, worker
        # metadata, poolArgs and SDK metadata. URI/image/KMS references are only
        # inspected as returned strings; no referenced content is requested.
        return {'environment': _bounded(environment)}
    if kind == BATCH:
        groups = row.get('taskGroups')
        if not isinstance(groups, list) or not 1 <= len(groups) <= 20:
            raise Incomplete('task_groups_required')
        result = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get('taskSpec'), dict):
                raise Incomplete('task_spec_required')
            if 'name' in group and (not isinstance(group['name'], str)
                    or not re.fullmatch(re.escape(row['name']) + r'/taskGroups/[A-Za-z0-9_-]{1,128}', group['name'])):
                raise Incomplete('task_group_identity')
            spec = group['taskSpec']
            part = {'environment': _env(spec.get('environment', {})),
                    'deprecated_environments': _map(spec.get('environments', {}))}
            envs = group.get('taskEnvironments', [])
            if not isinstance(envs, list) or len(envs) > 128:
                raise Incomplete('task_environment_bound')
            part['taskEnvironments'] = [_env(e) for e in envs]
            runnables = spec.get('runnables')
            if not isinstance(runnables, list) or not 1 <= len(runnables) <= 50:
                raise Incomplete('runnables_required')
            part['runnables'] = []
            for runnable in runnables:
                if not isinstance(runnable, dict) or len(set(runnable) & {'script', 'container', 'barrier'}) != 1:
                    raise Incomplete('runnable_union')
                value = {'environment': _env(runnable.get('environment', {}))}
                if 'script' in runnable:
                    script = runnable['script']
                    if (not isinstance(script, dict) or set(script) - {'path', 'text'}
                            or len(set(script) & {'path', 'text'}) != 1):
                        raise Incomplete('script_union')
                    if 'text' in script:
                        if not isinstance(script['text'], str):
                            raise Incomplete('script_text')
                        value['script.text'] = script['text']
                    elif not isinstance(script['path'], str) or not script['path'] or len(script['path'].encode()) > MAX_VALUE_BYTES:
                        raise Incomplete('script_reference_shape')
                if 'container' in runnable:
                    container = runnable['container']
                    if not isinstance(container, dict):
                        raise Incomplete('container_shape')
                    for field in ('commands', 'entrypoint', 'options', 'username', 'password'):
                        if field in container:
                            item = container[field]
                            if field == 'password' and isinstance(item, str) and re.fullmatch(r'projects/[^/]+/secrets/[^/]+/versions/[^/]+', item):
                                continue
                            if field == 'commands':
                                if not isinstance(item, list) or any(not isinstance(s, str) for s in item):
                                    raise Incomplete('container_commands')
                            elif not isinstance(item, str):
                                raise Incomplete('container_literal')
                            value['container.' + field] = item
                part['runnables'].append(value)
            result.append(part)
        return {'taskGroups.literal_configuration': _bounded(result)}
    if kind == CLUSTER:
        config = row.get('config')
        if not isinstance(config, dict) or 'virtualClusterConfig' in row:
            raise Incomplete('gce_cluster_config_required')
        software, gce = config.get('softwareConfig', {}), config.get('gceClusterConfig', {})
        if not isinstance(software, dict) or not isinstance(gce, dict):
            raise Incomplete('cluster_config_shape')
        return {'config.softwareConfig.properties': _map(software.get('properties', {})),
                'config.gceClusterConfig.metadata': _map(gce.get('metadata', {}))}
    variants = set(row) & set(_JOB_TYPES)
    if len(variants) != 1:
        raise Incomplete('dataproc_job_union')
    variant = next(iter(variants)); config = row[variant]
    if not isinstance(config, dict):
        raise Incomplete('dataproc_job_shape')
    result = {'properties': _map(config.get('properties', {}))}
    if 'scriptVariables' in config:
        result['scriptVariables'] = _map(config['scriptVariables'])
    if 'args' in config:
        if not isinstance(config['args'], list) or any(not isinstance(s, str) for s in config['args']):
            raise Incomplete('job_args')
        result['args'] = config['args']
    if 'queryList' in config:
        query = config['queryList']
        if (not isinstance(query, dict) or set(query) - {'queries'} or not isinstance(query.get('queries'), list)
                or any(not isinstance(s, str) for s in query['queries'])):
            raise Incomplete('query_list')
        result['queryList'] = query
    for field in ('mainClass', 'clientTags', 'continueOnFailure', 'outputFormat', 'loggingConfig'):
        if field in config:
            result[field] = _bounded(config[field])
    return {variant + '.literal_configuration': _bounded(result)}


def metadata_only(row, kind):
    """Default-off/pre-cache scrub; configuration values never persist here."""
    from .gcp import sanitize
    if not isinstance(row, dict):
        return {}
    if kind == CLUSTER:
        safe = deepcopy(row); safe.pop(MARKER, None); safe.pop(IDENTITY, None)
        config = safe.get('config')
        if isinstance(config, dict):
            for section, field in (('softwareConfig', 'properties'), ('gceClusterConfig', 'metadata')):
                parent = config.get(section)
                if isinstance(parent, dict) and field in parent:
                    parent.pop(field, None)
                    parent.setdefault('_coverage', {})[field] = {'status': 'unknown', 'reason': 'literal_values_not_retained'}
        return sanitize(safe)
    return {k: deepcopy(row[k]) for k in ('name', 'id', 'projectId', 'location', 'clusterName', 'clusterUuid',
        'reference', 'jobUuid', 'uid', 'description', 'labels', 'currentState', 'createTime', 'updateTime') if k in row}


def cluster_metadata_response(data):
    """Root's default-off pre-cache hook for the existing clusters.list call."""
    if not isinstance(data, dict) or not isinstance(data.get('clusters', []), list):
        raise Incomplete('cluster_metadata_shape')
    safe = deepcopy(data)
    if 'clusters' in data:
        safe['clusters'] = [metadata_only(row, CLUSTER) for row in data['clusters']]
    return safe


def _marker(ident, scope, kind, region):
    return {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'kind': kind, 'region': region,
            'complete': False, 'bytes': 0, 'fields': [], 'engines': [], 'leaks': [], 'verification': 'not_attempted'}


def project_row(row, scope, kind, region, project, aliases, state, remaining):
    native_id = _native_id(row, kind, region, aliases)
    ident = _identity(kind, project, region, native_id)
    marker = _marker(ident, scope, kind, region)
    safe = {IDENTITY: ident, 'name': ident} if kind != CLUSTER else {IDENTITY: ident}
    try:
        values = literals(row, kind)
        metadata = metadata_only(row, kind)
        segment = 'locations' if kind in (DATAFLOW, BATCH) else 'regions'
        collection = 'clusters' if kind == CLUSTER else 'jobs'
        metadata['nativeResourceName'] = f'projects/{project}/{segment}/{region}/{collection}/{native_id}'
        # Scan free-form retained names/labels/descriptions too, so reflections
        # of a detected value cannot escape through those metadata fields.
        payload = json.dumps(_bounded({'literals': values, 'metadata': metadata}),
                             ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        if len(payload) > MAX_ROW_BYTES or state['scan_bytes'] + len(payload) > MAX_SCAN_BYTES:
            raise Incomplete('scan_byte_limit')
        state['scan_bytes'] += len(payload)
        scrubbed = [metadata]
        outcome = scan_with_source(scan_content, payload, kind + '.literal_configuration', timeout=min(5, remaining() / 2),
                               _redact_values=lambda matches: scrubbed.__setitem__(0, redact_matches(scrubbed[0], matches)), source={'resource_id': metadata['nativeResourceName'], 'location_kind': 'configuration', 'scope': scope}, native=row)
        remaining()
        leaks = merge_leaks(outcome['leaks'])
        if len(leaks) > MAX_LEAKS or sum(len(l['locations']) for l in leaks) > MAX_LEAK_LOCATIONS:
            raise Incomplete('finding_limit')
        safe.update(scrubbed[0]); safe[IDENTITY] = ident
        if kind != CLUSTER:
            safe['name'] = ident
        marker.update(complete=outcome['complete'], bytes=len(payload), fields=sorted(values),
                      engines=outcome['engines'], leaks=leaks)
    except Exception:
        pass
    safe[MARKER] = marker
    return safe


class Reader:
    """Only constructed native GETs; no proxy/cookies/cache/error body storage."""
    def __init__(self, transport, state, session=None):
        if session is None:
            import requests
            session = requests.Session()
        session.trust_env = False; session.auth = None
        self.transport, self.state, self.session = transport, state, session

    def remaining(self):
        t, s = self.transport, self.state
        t.check_cancelled()
        result = MAX_SECONDS - (time.monotonic() - s['started'])
        if t.deadline is not None: result = min(result, t.deadline - time.time())
        if t.deadline_seconds is not None: result = min(result, t.deadline_seconds - (time.monotonic() - t.started))
        if result <= 0: raise Incomplete('deadline')
        return min(t.timeout, result)

    def get(self, kind, scope, project, region, token=None, job_id=None):
        if (kind not in KINDS or not enabled(self.transport.options, kind) or not _PROJECT.fullmatch(project)
                or not _REGION.fullmatch(region) or scope not in ('projects/' + project, 'projects/' + self.state['number'])
                or job_id is not None and (kind != DATAFLOW or not _ID.fullmatch(job_id))
                or token is not None and (not isinstance(token, str) or not token or len(token.encode()) > 4096)):
            raise Incomplete('unbound_read')
        service = {DATAFLOW: 'dataflow', BATCH: 'batch', CLUSTER: 'dataproc', DATAPROC: 'dataproc'}[kind]
        version, segment = ('v1b3', 'locations') if kind == DATAFLOW else ('v1', 'locations' if kind == BATCH else 'regions')
        url = f'https://{service}.googleapis.com/{version}/projects/{project}/{segment}/{region}/' + ('clusters' if kind == CLUSTER else 'jobs')
        params = {'pageSize': MAX_ROWS}
        if job_id is not None:
            url += '/' + job_id; params = {'view': 'JOB_VIEW_ALL'}
        elif kind == DATAFLOW:
            params.update(filter='ALL', view='JOB_VIEW_SUMMARY')
        if token is not None: params['pageToken'] = token
        operation = {DATAFLOW: 'dataflow.projects.locations.jobs', BATCH: 'batch.projects.locations.jobs',
                     CLUSTER: 'dataproc.projects.regions.clusters', DATAPROC: 'dataproc.projects.regions.jobs'}[kind]
        receipt = {'scope': scope, 'method': 'GET', 'operation': operation + ('.get' if job_id else '.list'),
                   'kind': kind, 'region': region, 'status': 'unavailable'}
        if job_id is not None:
            receipt['resource_id'] = _identity(kind, project, region, job_id)
        response = None
        try:
            self.remaining()
            with self.transport.lock:
                if self.state['calls'] >= MAX_CALLS or self.transport.max_calls is not None and self.transport.calls >= self.transport.max_calls:
                    raise Incomplete('call_limit')
                self.state['calls'] += 1; self.transport.calls += 1
            if http.client.HTTPConnection.debuglevel or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG):
                raise Incomplete('unsafe_diagnostics')
            credentials = {k.lower(): v for k, v in self.transport.credentials.headers().items()}
            authorization = credentials.get('authorization')
            if not isinstance(authorization, str) or not re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', authorization):
                raise Incomplete('credentials')
            if hasattr(self.session, 'cookies'): self.session.cookies.clear()
            headers = {'Authorization': authorization, 'Accept-Encoding': 'identity', 'Accept': 'application/json'}
            quota = self.transport.options.get('quota_project') or credentials.get('x-goog-user-project')
            if quota is not None:
                if not isinstance(quota, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}|[1-9][0-9]{0,19}', quota):
                    raise Incomplete('quota_project')
                headers['X-Goog-User-Project'] = quota
            response = self.session.request('GET', url, params=params, headers=headers, stream=True,
                allow_redirects=False, timeout=self.remaining())
            receipt['http_status'] = response.status_code
            if response.status_code != 200: raise Incomplete('denied' if response.status_code in (401, 403) else 'http_failure')
            import requests
            if response.url != requests.Request('GET', url, params=params).prepare().url or response.history:
                raise Incomplete('response_identity')
            hdr = {k.lower(): v for k, v in response.headers.items()}
            length = hdr.get('content-length')
            if (hdr.get('content-encoding', 'identity').lower() != 'identity' or 'content-range' in hdr
                    or hdr.get('content-type', '').split(';')[0].strip().lower() != 'application/json'
                    or not isinstance(length, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length)
                    or int(length) > MAX_HTTP_BYTES or self.state['wire_bytes'] + int(length) > MAX_WIRE_BYTES):
                raise Incomplete('response_framing')
            output = bytearray()
            while True:
                remaining = self.remaining()
                sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
                if sock is not None: sock.settimeout(remaining)
                chunk = response.raw.read(min(16384, MAX_HTTP_BYTES - len(output) + 1), decode_content=False)
                self.remaining()
                if not chunk: break
                if not isinstance(chunk, bytes): raise Incomplete('stream')
                self.state['wire_bytes'] += len(chunk); output.extend(chunk)
                if len(output) > MAX_HTTP_BYTES or self.state['wire_bytes'] > MAX_WIRE_BYTES: raise Incomplete('wire_byte_limit')
            if len(output) != int(length): raise Incomplete('truncated')
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result: raise Incomplete('duplicate_json')
                    result[key] = value
                return result
            data = json.loads(output.decode('utf-8', errors='strict'), object_pairs_hook=unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('nonfinite')))
            if not isinstance(data, dict): raise Incomplete('json_shape')
            receipt['status'] = 'collected'
            return data
        finally:
            if response is not None:
                try: response.close()
                except Exception: pass
            with self.transport.lock:
                receipt['id'] = 'request-' + str(len(self.transport.evidence) + 1)
                self.transport.evidence.append(receipt); self.state['refs'].append(receipt['id'])
                self.last_request_id = receipt['id']

    def close(self):
        self.session.close()


def collection_pages(collector, scope, kind, reader_factory=None):
    """Root schedules after project identity; only new opt-in kinds list jobs."""
    if kind not in KINDS or not enabled(collector.options, kind):
        return
    from .gcp import ReadError
    reader = None
    try:
        project, aliases = _project(collector, scope)
        regions = regions_for(collector.options, kind)
        with collector.transport.lock:
            if not hasattr(collector.transport, '_job_literal_state'):
                collector.transport._job_literal_state = {'started': time.monotonic(), 'calls': 0,
                    'wire_bytes': 0, 'scan_bytes': 0, 'rows': 0, 'refs': [], 'lock': threading.Lock()}
            state = collector.transport._job_literal_state
        with state['lock']:
            state['number'] = next(a for a in aliases if a != project)
            reader = (reader_factory or Reader)(collector.transport, state)
            seen_rows = set()
            for region in regions:
                token, seen_tokens = None, set()
                for page in range(MAX_PAGES):
                    start = len(state['refs'])
                    data = reader.get(kind, scope, project, region, token=token)
                    list_refs = state['refs'][start:]
                    if len(list_refs) != 1:
                        raise Incomplete('list_receipt_unavailable')
                    key = 'clusters' if kind == CLUSTER else 'jobs'
                    coverage_field = 'failedLocation' if kind == DATAFLOW else 'unreachable' if kind in (BATCH, DATAPROC) else None
                    allowed = {key, 'nextPageToken'} | ({coverage_field} if coverage_field else set())
                    coverage = data.get(coverage_field, []) if coverage_field else []
                    if (set(data) - allowed or not isinstance(data.get(key, []), list)
                            or not isinstance(coverage, list) or coverage):
                        raise Incomplete('partial_or_unrecognized_page')
                    rows = data.get(key, [])
                    if len(rows) > MAX_ROWS or state['rows'] + len(rows) > MAX_ROWS: raise Incomplete('resource_limit')
                    state['rows'] += len(rows)
                    # Envelope aggregation records yielded request IDs; per-item
                    # _coverage separately binds this list to the exact GET.
                    yield [], list_refs[0]
                    for row in rows:
                        native = _native_id(row, kind, region, aliases)
                        ident = _identity(kind, project, region, native)
                        if ident in seen_rows: raise Incomplete('duplicate_resource')
                        seen_rows.add(ident)
                        refs = list_refs[:]
                        if kind == DATAFLOW:
                            full_start = len(state['refs'])
                            try:
                                full = reader.get(kind, scope, project, region, job_id=native)
                                if _native_id(full, kind, region, aliases) != native: raise Incomplete('get_identity')
                                row = full
                            except Exception:
                                item = {'name': ident, IDENTITY: ident, MARKER: _marker(ident, scope, kind, region)}
                            else:
                                item = project_row(row, scope, kind, region, project, aliases, state, reader.remaining)
                            refs.extend(state['refs'][full_start:])
                        else:
                            item = project_row(row, scope, kind, region, project, aliases, state, reader.remaining)
                        item.setdefault('_coverage', {})[MARKER] = {
                            'status': 'collected' if item[MARKER]['complete'] else 'incomplete',
                            'source_requests': refs[:],
                            'semantics': 'native list and exact full GET' if kind == DATAFLOW else 'native configuration list page'}
                        yield [item], refs[-1]
                    token = data.get('nextPageToken')
                    if not token: break
                    if not isinstance(token, str) or token in seen_tokens or len(token.encode()) > 4096 or page + 1 == MAX_PAGES:
                        raise Incomplete('page_limit_or_cursor')
                    seen_tokens.add(token)
    except Exception:
        error = ReadError('unavailable', 'job_literal_configuration_unavailable')
        if reader is not None and getattr(reader, 'last_request_id', None):
            error.request_id = reader.last_request_id
        raise error from None
    finally:
        if reader is not None:
            try: reader.close()
            except Exception: pass
