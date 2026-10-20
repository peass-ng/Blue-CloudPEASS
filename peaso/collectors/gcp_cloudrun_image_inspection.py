"""Explicit Cloud Run image selection and native capture-consistency proof.

Only the named optional image check enters this path. Content is read by the
existing image reader; this module performs bounded metadata GETs only.
"""
from copy import deepcopy
import json
import time

from . import gcp_cloudrun_content_sources as planner
from .gcp_sbom_native import _read_run

MARKER = 'CloudRunImageSources'
SCHEMA = 'gcp-cloudrun-image-sources-v1'
MAX_PROOF_BYTES = 65536
MAX_METADATA_SECONDS = 60


def _native_coverage(value):
    if isinstance(value, dict):
        if value.get('_coverage') or value.get('collection_status', 'collected') != 'collected':
            raise ValueError('Cloud Run metadata has unavailable native fields')
        for child in value.values():
            _native_coverage(child)
    elif isinstance(value, list):
        for child in value:
            _native_coverage(child)


def validate_selection(values, scopes):
    if not isinstance(scopes, list) or len(scopes) != 1:
        raise ValueError('Cloud Run image selection requires one explicit project')
    return planner._selection(scopes[0], values)


def _read(collector, request, *, fresh=False):
    url, scope, params = request['url'], request['scope'], request['params']
    if fresh:
        # Revalidation must reach HTTP, not replay the first GET's cache entry.
        # Collector enrichment runs after metadata jobs have settled. Refuse an
        # in-flight entry instead of evicting another request's synchronization.
        transport = collector.transport
        key = json.dumps(['GET', url, params, None], sort_keys=True)
        with transport.lock:
            cached = transport.cache.get(key)
            if cached is not None:
                if not cached['event'].is_set():
                    raise ValueError('service metadata request is still in flight')
                del transport.cache[key]
    value, rid = _read_run(collector, url, scope, params['fields'])
    _native_coverage(value)
    return {'url': url, 'fields': params['fields'], 'source_request': rid, 'body': value}


def prepare(collector, scope, images, repositories, projects):
    services = validate_selection(collector.options['selected_cloudrun_services'], collector.scopes)
    if scope != collector.scopes[0]:
        raise ValueError('Cloud Run image scope differs from selected project')
    deadline = time.monotonic() + MAX_METADATA_SECONDS
    records = []

    def read(request):
        collector.transport.check_cancelled()
        if time.monotonic() >= deadline:
            raise TimeoutError('Cloud Run metadata deadline')
        record = _read(collector, request)
        records.append(record)
        return record['body']

    service_requests = planner.service_requests(scope, services)
    service_reads = {r['url']: read(r) for r in service_requests}
    revision_requests = planner.revision_requests(scope, services, projects=projects, service_reads=service_reads)
    revision_reads = {r['url']: read(r) for r in revision_requests}
    plan = planner.plan_sources(scope, services, projects=projects, repositories=repositories,
        service_reads=service_reads, revision_reads=revision_reads, image_rows=images)
    proof = {'schema': SCHEMA, 'scope': scope, 'services': services, 'reads': records,
             'revalidation': [], 'selected_artifact_images': plan['selected_artifact_images']}
    if len(json.dumps(proof).encode()) > MAX_PROOF_BYTES:
        raise ValueError('Cloud Run source proof byte bound')
    return plan, proof


def finish(collector, proof):
    scope, services = proof['scope'], proof['services']
    before = {r['url']: r for r in proof['reads']}
    start = time.monotonic()
    for request in planner.service_requests(scope, services):
        if time.monotonic() - start >= MAX_METADATA_SECONDS:
            raise TimeoutError('Cloud Run revalidation deadline')
        record = _read(collector, request, fresh=True)
        if (record['source_request'] == before[record['url']]['source_request']
                or record['body'] != before[record['url']]['body']):
            raise ValueError('Cloud Run service changed during image inspection')
        proof['revalidation'].append(record)
    if len(json.dumps(proof).encode()) > MAX_PROOF_BYTES:
        raise ValueError('Cloud Run source proof byte bound')
    return deepcopy(proof)


def validate_proof(item, index, images, repositories, projects):
    """Reconstruct the exact plan and require successful native GET receipts."""
    proof = item.get(MARKER)
    if (not isinstance(proof, dict) or set(proof) != {'schema', 'scope', 'services', 'reads',
            'revalidation', 'selected_artifact_images'} or proof['schema'] != SCHEMA
            or proof['scope'] != index['context']['scope']
            or len(json.dumps(proof).encode()) > MAX_PROOF_BYTES):
        raise ValueError('Cloud Run source proof is malformed or foreign')
    scope, services = proof['scope'], proof['services']
    requests = planner.service_requests(scope, services)
    reads, post = proof['reads'], proof['revalidation']
    if (not isinstance(reads, list) or not 2 <= len(reads) <= planner.MAX_SERVICES + planner.MAX_REVISIONS
            or not isinstance(post, list) or len(post) != len(services)):
        raise ValueError('Cloud Run source request count differs')
    operations = index['context']['metadata']['source_requests']
    ledger = {r['id']: r for r in operations}
    if len(ledger) != len(operations):
        raise ValueError('ambiguous native source request identities')
    unique, before, after = set(), {}, {}
    for phase, records, target in [('before', reads, before), ('after', post, after)]:
        for record in records:
            if not isinstance(record, dict) or set(record) != {'url', 'fields', 'source_request', 'body'}:
                raise ValueError('malformed Cloud Run source read')
            rid = record['source_request']
            entry = ledger.get(rid, {})
            if (rid in unique or record['url'] in target or entry.get('scope') != scope
                    or entry.get('method') != 'GET' or entry.get('status') != 'collected'
                    or entry.get('url') != record['url']
                    or type(entry.get('http_attempts')) is not int or entry['http_attempts'] < 1
                    or entry.get('query') != {'fields': record['fields']}):
                raise ValueError('Cloud Run source request provenance differs')
            unique.add(rid)
            _native_coverage(record['body'])
            target[record['url']] = record['body']
    if not unique <= set(item['_provenance']['source_requests']):
        raise ValueError('Cloud Run image is missing source request ownership')
    for request in requests:
        if (before.get(request['url']) != after.get(request['url']) or request['url'] not in after):
            raise ValueError('Cloud Run capture changed or was not revalidated')
    if set(after) != {r['url'] for r in requests}:
        raise ValueError('unexpected Cloud Run revalidation read')
    revision_requests = planner.revision_requests(scope, services, projects=projects, service_reads=before)
    expected = {r['url']: r['params']['fields'] for r in requests + revision_requests}
    if set(before) != set(expected) or any(r['fields'] != expected[r['url']] for r in reads):
        raise ValueError('Cloud Run read selectors differ from native plan')
    if any(r['fields'] != planner.SERVICE_FIELDS for r in post):
        raise ValueError('Cloud Run revalidation projection differs')
    plan = planner.plan_sources(scope, services, projects=projects, repositories=repositories,
        service_reads=before, revision_reads=before, image_rows=images)
    if (plan['selected_artifact_images'] != proof['selected_artifact_images']
            or item['uri'].removeprefix('https://') not in plan['selected_artifact_images']):
        raise ValueError('Cloud Run image is outside the complete selected-service plan')
    return [path for path in plan['deployment_paths'] if path['uri'] == item['uri']]
