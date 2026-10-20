"""Directed, synthetic-only acceptance matrix for the isolated proposal."""
from copy import deepcopy
import json

import pytest

import image_positive_helper as p
from peaso.secret_findings import deduplicate_secret_findings

@pytest.fixture(autouse=True)
def clear():
    original = (p.scanning._scan_kingfisher, p.scanning._scan_trufflehog)
    p.scanning._RESULTS.clear()
    yield
    p.scanning._scan_kingfisher, p.scanning._scan_trufflehog = original
    p.scanning._RESULTS.clear()

def unavailable(*args):
    raise RuntimeError('fixture unavailable')

def clean(*args):
    return []

def collect(value=p.fixtures.TOKEN, *, config_positive=True, missing_last=False, layer_partial=False):
    p.scanning._scan_kingfisher = p.positive if config_positive else lambda payload, path, timeout: [] if path == 'image-config.json' else p.positive(payload, path, timeout)
    p.scanning._scan_trufflehog = (lambda payload, path, timeout: clean(payload, path, timeout) if path == 'image-config.json' else unavailable(payload, path, timeout)) if layer_partial else clean
    row, bodies = p.fixtures.image(value)
    if missing_last:
        manifest = json.loads(next(body for url, body in bodies.items() if '/manifests/' in url))
        bodies.pop(next(url for url in bodies if url.endswith(manifest['layers'][1]['digest'])))
    session = p.fixtures.Session(bodies)
    reader = p.projection.Reader(p.fixtures.transport(), session=session)
    row[p.projection.MARKER] = p.projection.inspect_image(row, p.fixtures.SCOPE, p.fixtures.REPOSITORIES, p.fixtures.PROJECTS, reader)
    return row, session

def verdict(row, index=None):
    return p.check.evaluate(row, p.fixtures.index(row) if index is None else index)[0]

def test_config_one_positive_other_unavailable():
    p.scanning._scan_kingfisher, p.scanning._scan_trufflehog = p.positive, unavailable
    row, bodies = p.fixtures.image(p.fixtures.TOKEN)
    session = p.fixtures.Session(bodies)
    reader = p.projection.Reader(p.fixtures.transport(), session=session)
    marker = p.projection.inspect_image(row, p.fixtures.SCOPE, p.fixtures.REPOSITORIES, p.fixtures.PROJECTS, reader)
    row[p.projection.MARKER] = marker
    assert verdict(row) == 'FAIL'
    assert marker['inspected_digests'] == [marker['descriptors'][0]['digest']]
    assert marker['layers_scanned'] == [] and len(session.calls) == 2
    assert p.fixtures.TOKEN not in json.dumps(row)

def partial_config_positive():
    p.scanning._scan_kingfisher, p.scanning._scan_trufflehog = p.positive, unavailable
    row, bodies = p.fixtures.image(p.fixtures.TOKEN)
    reader = p.projection.Reader(p.fixtures.transport(), session=p.fixtures.Session(bodies))
    row[p.projection.MARKER] = p.projection.inspect_image(row, p.fixtures.SCOPE, p.fixtures.REPOSITORIES, p.fixtures.PROJECTS, reader)
    assert verdict(row) == 'FAIL'
    return row

def test_both_config_engines_unavailable_cannot_support_positive():
    row = partial_config_positive()
    for engine in row[p.projection.MARKER]['engines']:
        engine['status'] = 'unavailable'
    assert verdict(row) == 'UNKNOWN'

def test_unavailable_only_leak_detector_is_unknown():
    row = partial_config_positive()
    row[p.projection.MARKER]['leaks'][0]['detectors'] = [{'engine': 'trufflehog', 'rule': 'fixture-rule'}]
    assert verdict(row) == 'UNKNOWN'

def test_same_source_contradictory_reporting_engine_is_unknown():
    row = partial_config_positive()
    row[p.projection.MARKER]['source_reports'][0]['engines'][0]['engine'] = 'trufflehog'
    assert verdict(row) == 'UNKNOWN'

def test_first_layer_positive_later_failure():
    row, session = collect(config_positive=False, missing_last=True)
    marker = row[p.projection.MARKER]
    assert verdict(row) == 'FAIL' and len(session.calls) == 4
    assert marker['inspected_digests'] == [d['digest'] for d in marker['descriptors'][:2]]
    assert marker['layers_scanned'] == [marker['descriptors'][1]['digest']]
    assert p.fixtures.TOKEN not in json.dumps(row)

def test_partial_archive_carries_verified_layer_observation():
    row, _ = collect(config_positive=False, layer_partial=True)
    marker = row[p.projection.MARKER]
    assert verdict(row) == 'FAIL'
    assert marker['layers_scanned'] == []
    assert marker['inspected_digests'] == [d['digest'] for d in marker['descriptors'][:2]]
    assert marker['leaks'][0]['locations'][0]['layer'] == marker['descriptors'][1]['digest']
    marker['source_reports'][0]['engines'][0]['status'] = 'unavailable'
    assert verdict(row) == 'UNKNOWN'

@pytest.mark.parametrize('failed_engine', ['kingfisher', 'trufflehog'])
def test_either_detector_positive_survives_other_failure(failed_engine):
    p.scanning._scan_kingfisher = unavailable if failed_engine == 'kingfisher' else p.positive
    p.scanning._scan_trufflehog = unavailable if failed_engine == 'trufflehog' else p.positive
    row, bodies = p.fixtures.image(p.fixtures.TOKEN)
    reader = p.projection.Reader(p.fixtures.transport(), session=p.fixtures.Session(bodies))
    row[p.projection.MARKER] = p.projection.inspect_image(row, p.fixtures.SCOPE, p.fixtures.REPOSITORIES, p.fixtures.PROJECTS, reader)
    assert verdict(row) == 'FAIL'
    assert p.fixtures.TOKEN not in json.dumps(row)

def test_digest_mismatch_in_first_layer_confers_no_layer_evidence():
    p.scanning._scan_kingfisher = lambda payload, path, timeout: [] if path == 'image-config.json' else p.positive(payload, path, timeout)
    p.scanning._scan_trufflehog = clean
    row, bodies = p.fixtures.image(p.fixtures.TOKEN)
    manifest = json.loads(next(body for url, body in bodies.items() if '/manifests/' in url))
    first_url = next(url for url in bodies if url.endswith(manifest['layers'][0]['digest']))
    bodies[first_url] += b'altered'
    reader = p.projection.Reader(p.fixtures.transport(), session=p.fixtures.Session(bodies))
    row[p.projection.MARKER] = p.projection.inspect_image(row, p.fixtures.SCOPE, p.fixtures.REPOSITORIES, p.fixtures.PROJECTS, reader)
    assert verdict(row) == 'UNKNOWN' and row[p.projection.MARKER]['leaks'] == []

@pytest.mark.parametrize('value,missing_last,expected', [
    ('production', False, 'PASS'),
    (p.fixtures.TOKEN, False, 'FAIL'),
    ('production', True, 'UNKNOWN'),
])
def test_complete_and_incomplete_invariants(value, missing_last, expected):
    row, _ = collect(value, missing_last=missing_last)
    assert verdict(row) == expected

@pytest.mark.parametrize('tamper', [
    lambda row: row[p.projection.MARKER].update(uri=row['uri'] + '-foreign'),
    lambda row: row[p.projection.MARKER].update(repository=row['repository'] + '-foreign'),
    lambda row: row[p.projection.MARKER].update(manifest_digest='sha256:'+'0'*64),
    lambda row: row[p.projection.MARKER]['descriptors'][0].update(digest='sha256:'+'0'*64),
    lambda row: row[p.projection.MARKER]['inspected_digests'].clear(),
    lambda row: row[p.projection.MARKER]['inspected_digests'].append('sha256:'+'0'*64),
    lambda row: row[p.projection.MARKER]['leaks'][0]['locations'][0].update(layer='sha256:'+'0'*64),
    lambda row: row[p.projection.MARKER]['leaks'][0].update(fingerprint='invalid'),
    lambda row: row[p.projection.MARKER]['engines'][0].update(version='foreign'),
    lambda row: row[p.projection.MARKER]['source_reports'][0].update(layer=row[p.projection.MARKER]['descriptors'][2]['digest']),
    lambda row: row[p.projection.MARKER]['source_reports'].append(deepcopy(row[p.projection.MARKER]['source_reports'][0])),
    lambda row: row[p.projection.MARKER].update(leaks=[]),
    lambda row: row.update(digest='sha256:'+'0'*64),
])
def test_partial_tamper_is_unknown(tamper):
    row, _ = collect(config_positive=False, missing_last=True)
    assert verdict(row) == 'FAIL'
    tamper(row)
    assert verdict(row) == 'UNKNOWN'

def test_foreign_parent_is_unknown():
    row, _ = collect(config_positive=False, missing_last=True)
    index = p.fixtures.index(row)
    index['collections']['artifact_repository'][0]['items'][0]['name'] += '-foreign'
    assert verdict(row, index) == 'UNKNOWN'

def test_partial_finding_deduplicates_without_plaintext():
    row, _ = collect(config_positive=False, missing_last=True)
    status, evidence = p.check.evaluate(row, p.fixtures.index(row))
    finding = {'provider':'gcp', 'scope':p.fixtures.SCOPE, 'resource_id':row['uri'],
        'native_resource_id':row['uri'], 'resource_type':'artifact_image',
        'check_id':p.projection.CHECK_ID, 'status':status, 'frameworks':[], 'evidence':evidence}
    assert len(deduplicate_secret_findings([finding, deepcopy(finding)])) == 1
    assert evidence['credential_validation'] == 'not_attempted'
    assert p.fixtures.TOKEN not in json.dumps(finding) + repr(p.scanning._RESULTS)

def test_enrichment_partial_status_keeps_native_request_provenance():
    p.scanning._scan_kingfisher = lambda payload, path, timeout: [] if path == 'image-config.json' else p.positive(payload, path, timeout)
    p.scanning._scan_trufflehog = clean
    row, bodies = p.fixtures.image(p.fixtures.TOKEN)
    manifest = json.loads(next(body for url, body in bodies.items() if '/manifests/' in url))
    bodies.pop(next(url for url in bodies if url.endswith(manifest['layers'][1]['digest'])))
    collector = p.fixtures.collector(row)
    session = p.fixtures.Session(bodies)
    p.projection.enrich(collector, reader_factory=lambda t: p.projection.Reader(t, session=session))
    assert verdict(row) == 'FAIL'
    coverage = row['_coverage'][p.projection.MARKER]
    assert coverage['status'] == 'partial' and len(coverage['source_requests']) == 4
    assert set(coverage['source_requests']) <= set(row['_provenance']['source_requests'])
    assert p.fixtures.TOKEN not in json.dumps([row, collector.transport.evidence])
    coverage['status'] = 'unavailable'
    assert verdict(row) == 'UNKNOWN'
