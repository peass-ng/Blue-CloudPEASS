"""Build parity, bounded API transport, fail-closed data and native-import isolation."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from fastapi import HTTPException
import pytest
from peaso.server import materialized_catalog as runtime

ROOT = Path(__file__).resolve().parents[1]


def test_materializer_reproduces_exact_verified_runtime_views_and_selectors():
    from scripts.peaso_compliance_materialize import render_documents
    from peaso.engine import get_catalog, PROVIDERS
    from peaso.server.catalog_view import summary, frameworks_view
    from peaso.server.validation import _selector_index
    documents = render_documents()
    assert documents[ROOT / 'peaso/rulepacks/api_catalog.json.gz'] == (runtime.PACK / 'api_catalog.json.gz').read_bytes()
    assert documents[ROOT / 'peaso/rulepacks/api_catalog_manifest.json'] == (runtime.PACK / 'api_catalog_manifest.json').read_bytes()
    captured = json.loads(gzip.decompress(documents[ROOT / 'peaso/rulepacks/api_catalog.json.gz']))
    normalized = lambda value: json.loads(json.dumps(value))
    full = get_catalog()
    assert captured['full'] == normalized(full)
    assert captured['summary'] == normalized(dict(summary(), privesc_catalog=full['privesc_catalog']))
    assert captured['frameworks'] == normalized(frameworks_view())
    for provider in PROVIDERS:
        assert captured['selectors'][provider] == dict(zip(('categories', 'checks', 'frameworks'),
                                                         (sorted(values) for values in _selector_index(provider))))
    from peaso.checks.catalog import description_for, expand_framework_selectors
    for cid, expected in captured['descriptions'].items():
        assert runtime.description_for(cid) == expected == description_for(cid)
    for selector in [*captured['framework_expansion'], 'unreviewed.framework']:
        assert runtime.expand_framework_selectors({selector}) == expand_framework_selectors({selector})
    for relative, digest in captured['sources'].items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == digest


def test_all_pages_preserve_every_full_metadata_row_and_order_with_real_wire_bounds():
    expected = runtime._load()['full']['checks']
    rows = []
    offset = 0
    while True:
        page = runtime.full_page(offset, 500)
        assert runtime.wire_fits(runtime._encoded(page))
        assert page['pagination']['total'] == len(expected)
        assert page['pagination']['returned'] == len(page['checks'])
        rows.extend(page['checks'])
        next_offset = page['pagination']['next_offset']
        if next_offset is None:
            break
        assert next_offset == offset + len(page['checks']) > offset
        offset = next_offset
    assert rows == expected
    assert runtime.full_page(len(expected))['checks'] == []
    for row in expected:
        assert runtime.check_detail(row['id']) == row
    with pytest.raises(HTTPException) as absent:
        runtime.check_detail('unreviewed.invalid')
    assert absent.value.status_code == 404


@pytest.mark.parametrize('offset,limit', [(-1, 1), (0, 0), (0, 501), (999999, 1), (True, 1)])
def test_pagination_rejects_invalid_limits_without_truncation(offset, limit):
    with pytest.raises(HTTPException) as rejected:
        runtime.full_page(offset, limit)
    assert rejected.value.status_code == 422


def test_byte_budget_reduces_page_with_explicit_continuation(monkeypatch):
    full = runtime._load()['full']
    base = {key: value for key, value in full.items() if key != 'checks'}
    first_size = len(runtime._encoded(full['checks'][0]))
    monkeypatch.setattr(runtime, 'MAX_WIRE_BYTES', len(runtime._encoded(base)) + first_size + 1024)
    page = runtime.full_page(0, 500)
    assert 0 < len(page['checks']) < 500
    assert page['pagination']['next_offset'] == len(page['checks'])
    assert len(runtime._encoded(page)) <= runtime.MAX_WIRE_BYTES
    assert not runtime.wire_fits(runtime._encoded({'value': '\u2603' * (2 * 1024 * 1024)}))


@pytest.mark.parametrize('mode', ['missing', 'corrupt', 'oversized', 'manifest_corrupt', 'generation_mismatch'])
def test_packaged_artifact_failure_is_closed_without_native_fallback(tmp_path, monkeypatch, mode):
    for name in ('api_catalog.json.gz', 'api_catalog_manifest.json'):
        shutil.copyfile(runtime.PACK / name, tmp_path / name)
    path = tmp_path / 'api_catalog.json.gz'
    if mode == 'missing':
        path.unlink()
    elif mode == 'corrupt':
        path.write_bytes(b'unreviewed gzip')
    elif mode == 'oversized':
        with path.open('wb') as stream:
            stream.truncate(runtime.MAX_COMPRESSED_BYTES + 1)
    elif mode == 'manifest_corrupt':
        (tmp_path / 'api_catalog_manifest.json').write_text('{}')
    else:
        manifest = json.loads((tmp_path / 'api_catalog_manifest.json').read_bytes())
        manifest['sources']['peaso/rulepacks/native_catalog.json'] = '0' * 64
        (tmp_path / 'api_catalog_manifest.json').write_text(json.dumps(manifest))
    runtime._load.cache_clear()
    monkeypatch.setattr(runtime, 'PACK', tmp_path)
    try:
        with pytest.raises(HTTPException) as rejected:
            runtime.summary()
        assert rejected.value.status_code == 503
    finally:
        runtime._load.cache_clear()


def test_provider_selector_aliases_exclusions_and_exact_422_contract():
    value = runtime._load()
    ids = {row['id'] for row in value['full']['checks']}
    aliases = set(value['selectors']['aws']['checks']) - ids
    assert aliases
    runtime.validate_selectors({'checks': [next(iter(aliases))], 'frameworks': ['nist']}, 'aws')
    for request, provider, detail in [
        ({'checks': ['aws_bedrock_automated_reasoning_policy_attached']}, 'aws', 'Unknown check for selected provider'),
        ({'checks': ['azure.storage.https_only']}, 'aws', 'Unknown check for selected provider'),
        ({'checks': ['unreviewed.invalid']}, 'aws', 'Unknown check for selected provider'),
        ({'categories': ['unreviewed']}, 'aws', 'Unsupported scan category'),
        ({'frameworks': ['unreviewed']}, 'aws', 'Unsupported framework')]:
        with pytest.raises(HTTPException) as rejected:
            runtime.validate_selectors(request, provider)
        assert rejected.value.status_code == 422 and rejected.value.detail == detail


@pytest.mark.parametrize('scenario', ['full', 'summary', 'frameworks', 'scans', 'scan_create', 'setup', 'lookups', 'full_max'])
def test_fresh_mangum_blocks_all_native_imports_and_outbound_calls(scenario):
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/peaso_api_catalog_cold_probe_20261020.py'), scenario],
                            cwd=ROOT, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    proof = json.loads(result.stdout)
    assert proof['native_modules_loaded'] == [] and proof['network_attempts'] == 0
    assert proof['body_bytes'] <= runtime.MAX_WIRE_BYTES and proof['mangum_envelope_bytes'] <= 6 * 1024 * 1024


def test_privesc_catalog_change_invalidates_materialized_generation(tmp_path, monkeypatch):
    # A private miniature source root proves even an added YAML file fails the
    # existing exact manifest/tree binding; production inputs stay read-only.
    for relative in runtime.SOURCE_PATHS:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, path)
    shutil.copytree(ROOT / 'peaso/privesc/catalog', tmp_path / 'peaso/privesc/catalog')
    (tmp_path / 'peaso/privesc/catalog/unreviewed.yaml').write_text('unreviewed: true')
    runtime._load.cache_clear()
    monkeypatch.setattr(runtime, 'ROOT', tmp_path / 'peaso')
    try:
        with pytest.raises(HTTPException) as rejected:
            runtime.summary()
        assert rejected.value.status_code == 503
    finally:
        runtime._load.cache_clear()
