"""Build-verified API metadata; never import or execute native scan code.

Full metadata uses offset/limit pagination (1..500 checks, default 100). Each
page and individual check detail is capped at 4 MiB of UTF-8 JSON. next_offset
is authoritative when the byte cap returns fewer than the requested limit.
"""
from copy import deepcopy
from functools import lru_cache
import gzip
import hashlib
import io
import json
from pathlib import Path
import zlib

from fastapi import HTTPException, Response

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / 'rulepacks'
MAX_WIRE_BYTES = 4 * 1024 * 1024
MAX_ENVELOPE_BYTES = 6 * 1024 * 1024
MAX_COMPRESSED_BYTES = 8 * 1024 * 1024
MAX_DOCUMENT_BYTES = 48 * 1024 * 1024
MAX_LIMIT = 500
SOURCE_PATHS = frozenset({'peaso/rulepacks/native_catalog.json',
    'peaso/rulepacks/framework_catalog.json', 'peaso/rulepacks/runtime_metadata.json',
    'peaso/rulepacks/catalog_summary.json', 'peaso/checks/native_only.json',
    'peaso/privesc/versioned_catalog.py', 'peaso/privesc/schema.py',
    'risk_rules/hacktricks-privesc-source.json'})


def _encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def wire_fits(body):
    # Lambda serializes the JSON response body again inside its return envelope.
    # Reserve 16 KiB for Mangum status/headers, including middleware headers.
    return (len(body) <= MAX_WIRE_BYTES
            and len(json.dumps(body.decode(), ensure_ascii=True).encode()) + 16384 <= MAX_ENVELOPE_BYTES)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate catalog key')
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite catalog value')))


def _digest_file(path):
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('catalog source budget')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _unavailable():
    return HTTPException(503, 'Materialized catalog unavailable; rebuild the reviewed API catalog')


@lru_cache(maxsize=1)
def _load():
    try:
        manifest_path = PACK / 'api_catalog_manifest.json'
        if manifest_path.stat().st_size > 16384:
            raise ValueError('catalog manifest budget')
        with manifest_path.open('rb') as stream:
            manifest_raw = stream.read(16385)
        if len(manifest_raw) > 16384:
            raise ValueError('catalog manifest budget')
        manifest = _json(manifest_raw)
        if (manifest['schema_version'] != 1 or set(manifest['sources']) != SOURCE_PATHS
                or not 0 < manifest['uncompressed_bytes'] <= MAX_DOCUMENT_BYTES):
            raise ValueError('catalog manifest schema')
        for relative, expected in manifest['sources'].items():
            if _digest_file(ROOT.parent / relative) != expected:
                raise ValueError('catalog source generation mismatch')
        path = PACK / 'api_catalog.json.gz'
        if not 0 < path.stat().st_size <= MAX_COMPRESSED_BYTES:
            raise ValueError('compressed catalog budget')
        with path.open('rb') as stream:
            raw = stream.read(MAX_COMPRESSED_BYTES + 1)
        if len(raw) > MAX_COMPRESSED_BYTES:
            raise ValueError('compressed catalog budget')
        if hashlib.sha256(raw).hexdigest() != manifest['gzip_sha256']:
            raise ValueError('catalog gzip identity')
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            document = stream.read(MAX_DOCUMENT_BYTES + 1)
        if (len(document) != manifest['uncompressed_bytes']
                or hashlib.sha256(document).hexdigest() != manifest['document_sha256']):
            raise ValueError('catalog document identity')
        value = _json(document)
        if value['schema_version'] != 1 or value['sources'] != manifest['sources']:
            raise ValueError('catalog envelope generation')
        full = value['full']
        checks = full['checks']
        if not isinstance(checks, list) or not 0 < len(checks) <= 20000:
            raise ValueError('catalog checks budget')
        ids = [row['id'] for row in checks]
        if len(ids) != len(set(ids)) or any(not isinstance(cid, str) for cid in ids):
            raise ValueError('catalog check identities')
        providers = full['providers']
        if set(value['selectors']) != set(providers) or set(providers) != {'aws', 'azure', 'gcp', 'k8s'}:
            raise ValueError('catalog providers')
        for provider, index in value['selectors'].items():
            if set(index) != {'categories', 'checks', 'frameworks'}:
                raise ValueError('selector schema')
            for entries in index.values():
                if (not isinstance(entries, list) or len(entries) > 20000
                        or any(not isinstance(entry, str) or len(entry) > 4096 for entry in entries)
                        or len(entries) != len(set(entries))):
                    raise ValueError('selector values')
        if ([row['id'] for row in value['summary']['checks']] != ids
                or value['summary']['view'] != 'summary' or value['frameworks']['view'] != 'frameworks'
                or value['summary']['privesc_catalog'] != full['privesc_catalog']):
            raise ValueError('catalog view parity')
        if any(not wire_fits(_encoded(value[name])) for name in ('summary', 'frameworks')):
            raise ValueError('compact catalog wire budget')
        # Verify the exact build-time privilege catalog without importing its
        # YAML/schema/evaluator code at API request time.
        binding = full['privesc_catalog']
        privesc_source = 'risk_rules/hacktricks-privesc-source.json'
        if binding['manifest_sha256'] != manifest['sources'][privesc_source]:
            raise ValueError('privilege catalog manifest binding')
        privesc_manifest = _json((ROOT.parent / privesc_source).read_bytes())
        catalog_root = ROOT / 'privesc/catalog'
        paths = sorted(catalog_root.rglob('*.yaml'))
        if len(paths) > 2048 or sum(path.stat().st_size for path in paths) > 16 * 1024 * 1024:
            raise ValueError('privilege catalog source budget')
        actual = {path.relative_to(catalog_root).as_posix(): _digest_file(path) for path in paths}
        tree = ''.join(name + ' ' + actual[name] + '\n' for name in sorted(actual))
        if (actual != privesc_manifest['sha256']
                or hashlib.sha256(tree.encode()).hexdigest() != binding['effective_tree_sha256']):
            raise ValueError('privilege catalog tree binding')
        if (not isinstance(value['descriptions'], dict)
                or not isinstance(value['framework_expansion'], dict)
                or not isinstance(value['framework_display'], dict)
                or not isinstance(value['framework_aliases'], dict)):
            raise ValueError('reviewed presentation lookup schema')
        value['_by_id'] = dict(zip(ids, checks))
        value['_selector_sets'] = {provider: {key: frozenset(entries) for key, entries in index.items()}
                                   for provider, index in value['selectors'].items()}
        return value
    except (OSError, ValueError, TypeError, KeyError, AttributeError, EOFError, zlib.error):
        raise _unavailable() from None


def summary():
    return deepcopy(_load()['summary'])


def frameworks_view():
    return deepcopy(_load()['frameworks'])


def full_page(offset=0, limit=100):
    if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= MAX_LIMIT:
        raise HTTPException(422, 'Invalid catalog pagination')
    full = _load()['full']
    total = len(full['checks'])
    if offset > total:
        raise HTTPException(422, 'Catalog offset exceeds total')
    result = {key: value for key, value in full.items() if key != 'checks'}
    result.update(checks=[], pagination={'offset': offset, 'limit': limit, 'returned': 0,
                                         'total': total, 'next_offset': None})
    used = len(_encoded(result)) + 256
    if used > MAX_WIRE_BYTES:
        raise _unavailable()
    for row in full['checks'][offset:offset + limit]:
        size = len(_encoded(row)) + 1
        if used + size > MAX_WIRE_BYTES:
            break
        result['checks'].append(row)
        used += size
    while result['checks'] and not wire_fits(_encoded(result)):
        result['checks'].pop()
    count = len(result['checks'])
    if count == 0 and offset < total:
        raise _unavailable()
    result['pagination'].update(returned=count, next_offset=offset + count if offset + count < total else None)
    if not wire_fits(_encoded(result)):
        raise _unavailable()
    return deepcopy(result)


def check_detail(check_id):
    row = _load()['_by_id'].get(check_id)
    if row is None:
        raise HTTPException(404, 'Unknown catalog check')
    if not wire_fits(_encoded(row)):
        raise _unavailable()
    return deepcopy(row)


def validate_selectors(request, provider):
    index = _load()['_selector_sets'].get(provider)
    if index is None:
        raise HTTPException(422, 'Unknown scan provider')
    if any(value not in index['categories'] for value in request.get('categories', [])):
        raise HTTPException(422, 'Unsupported scan category')
    if any(value not in index['checks'] for value in request.get('checks', [])):
        raise HTTPException(422, 'Unknown check for selected provider')
    if any(value not in index['frameworks'] and str(value).lower() not in index['frameworks']
           for value in request.get('frameworks', [])):
        raise HTTPException(422, 'Unsupported framework')


def bounded_response(request, value):
    body = _encoded(value)
    if not wire_fits(body):
        raise _unavailable()
    etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'
    headers = {'ETag': etag, 'Cache-Control': 'private, no-cache'}
    if etag in {tag.strip() for tag in request.headers.get('if-none-match', '').split(',')}:
        return Response(status_code=304, headers=headers)
    return Response(body, media_type='application/json', headers=headers)


def description_for(check_id):
    """Exact build-time reviewed prose, including archived known checks."""
    return deepcopy(_load()['descriptions'].get(check_id))


def framework_aliases():
    return dict(_load()['framework_aliases'])


def expand_framework_selectors(values):
    value = _load()
    expanded = set(values)
    for selector in values:
        for framework_id in value['framework_expansion'].get(str(selector).lower(), ()):
            expanded.add(framework_id)
            expanded.add(value['framework_display'][framework_id])
    return expanded
