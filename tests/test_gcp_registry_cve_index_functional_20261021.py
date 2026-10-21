"""Offline native registry index to child Trivy result to selected consumer."""
from copy import deepcopy
import json
from urllib.parse import quote

import pytest

import gcp_job_image_vulnerability_fixture_20261021 as fixture
from peaso import oci_index_20261021 as oci
from peaso.collectors import gcp_registry_trivy_20261021 as source
from peaso.collectors import gcp_registry_trivy_runtime_20261021 as runtime
from peaso.checks import gcp_registry_trivy_review_20261021 as review


def enc(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def index_fixture(*, wrong_platform=False, wrong_child=False, wrong_parent=False,
                  media_type=oci.OCI_INDEX):
    row, blobs = fixture.image()
    first_digest = row['digest']
    root = row['uri'].rsplit('@', 1)[0].removeprefix('https://')
    base = 'https://' + root.replace('/app', '/v2/review/images/app') + '/'
    # The fixture map is keyed by exact registry URLs, not bare digests.
    manifest_url = next(key for key in blobs if key.endswith('/manifests/' + first_digest))
    base = manifest_url.rsplit('manifests/', 1)[0]
    first = blobs[manifest_url]
    leaf_type = fixture.image_native.DOCKER if media_type == oci.DOCKER_LIST else fixture.image_native.OCI
    if media_type == oci.DOCKER_LIST:
        first_doc = json.loads(first)
        first_doc['mediaType'] = leaf_type
        first = enc(first_doc)
        first_digest = fixture.image_native._sha(first)
        blobs[base + 'manifests/' + first_digest] = first
    second = json.loads(first)
    old_config = second['config']['digest']
    config = json.loads(blobs[base + 'blobs/' + old_config])
    config['architecture'] = 'arm64'
    config_raw = enc(config)
    config_digest = fixture.image_native._sha(config_raw)
    second['config'].update(digest=config_digest, size=len(config_raw))
    second_raw = enc(second)
    second_digest = fixture.image_native._sha(second_raw)
    blobs[base + 'blobs/' + config_digest] = config_raw
    blobs[base + 'manifests/' + second_digest] = b'{}' if wrong_child else second_raw
    parent = enc({'schemaVersion': 2, 'mediaType': media_type,
        'manifests': [
            {'mediaType': leaf_type, 'digest': first_digest,
             'size': len(first), 'platform': {'os': 'linux', 'architecture': 'amd64'}},
            {'mediaType': leaf_type, 'digest': second_digest,
             'size': len(second_raw), 'platform': {'os': 'linux',
                'architecture': 'amd64' if wrong_platform else 'arm64'}}]})
    parent_digest = fixture.image_native._sha(parent)
    blobs[base + 'manifests/' + parent_digest] = b'{}' if wrong_parent else parent
    reference = root + '@' + parent_digest
    project = {'name': 'projects/123456789', 'projectId': 'review', 'state': 'ACTIVE'}
    repository = {'name': fixture.REPO, 'format': 'DOCKER',
        'mode': 'STANDARD_REPOSITORY', 'updateTime': '2026-10-20T09:00:00Z'}
    docker = {'name': fixture.REPO + '/dockerImages/' + quote('app@' + parent_digest, safe=''),
        'uri': reference, 'mediaType': media_type, 'updateTime': '2026-10-20T09:01:00Z'}
    bodies = {url: body for (url, _), body in zip(source.requests_for(reference, fixture.SCOPE),
        (project, repository, docker))}
    return reference, bodies, blobs, first_digest, second_digest


def runner(hit=False, fresh=True):
    def scan(identity, manifest, config, layers, **kwargs):
        assert kwargs['native_verifier']() == identity
        assert kwargs['db_cache'] == 'trusted-offline-cache'
        finding = {'vulnerability_id': 'CVE-2026-12345', 'severity': 'HIGH',
            'package_types': ['alpine'], 'package': 'fixture-package', 'version': '1.0',
            'fixed_in': ['1.1'], 'fix_status': 'fixed', 'classes': ['os-pkgs'],
            'image_digest': identity['manifest_digest']}
        findings = [finding] if hit and json.loads(config)['architecture'] == 'amd64' else []
        complete = fresh
        return {'image': identity, 'status': 'FAIL' if findings else 'PASS' if complete else 'UNKNOWN',
            'complete': complete, 'scan_complete': True,
            'coverage_status': 'COMPLETE' if complete else 'UNKNOWN',
            'database': {'fresh': fresh}, 'findings': findings}
    return scan


def collect(reference, bodies, blobs, *, hit=False, fresh=True):
    meta = fixture.MetadataSession(bodies)
    image = fixture.ImageSession(blobs)
    wire = fixture.transport()
    result = runtime.collect_selected(wire, scope=fixture.SCOPE, targets=[reference],
        metadata_session=meta, image_session=image, runner=runner(hit, fresh),
        db_cache='trusted-offline-cache')
    assert meta.closed and image.closed
    return result, wire, image


def verdict(result, reference):
    row = result['rows'][0]
    item = {'name': reference, '_resource_id': reference, 'native_id': reference,
        'RegistryImageVulnerabilityReview': row}
    index = {'context': {'provider': 'gcp', 'scope': fixture.SCOPE,
        'metadata': {runtime.OPTION: [reference]}},
        'collections': {runtime.KIND: [{'scope': fixture.SCOPE,
            'status': 'collected' if row['complete'] else 'partial', 'items': [item]}]}}
    return review.evaluate_item(item, index)


@pytest.mark.parametrize('hit,expected', [(False, 'PASS'), (True, 'FAIL')])
def test_index_two_platform_native_to_consumer(hit, expected):
    reference, bodies, blobs, first, second = index_fixture()
    result, wire, image = collect(reference, bodies, blobs, hit=hit)
    assert result['status'] == expected, result
    assert verdict(result, reference)[0] == expected
    record = result['rows'][0]['vulnerability_record']
    assert [child['digest'] for child in record['graph']['children']] == [first, second]
    assert {finding['image_digest'] for finding in record['findings']} == ({first} if hit else set())
    assert len(image.calls) == 7 and len(wire.evidence) == 13
    from peaso.image_findings import build_report
    table = build_report(result['observations'], selected=True)
    assert table['coverage'] == 'COMPLETE'
    assert [row['image_digest'] for row in table['rows']] == ([first] if hit else [])


@pytest.mark.parametrize('problem', ['parent', 'child', 'platform'])
def test_invalid_parent_child_or_config_platform_cannot_pass(problem):
    reference, bodies, blobs, _, _ = index_fixture(wrong_parent=problem=='parent',
        wrong_child=problem=='child', wrong_platform=problem=='platform')
    result, _, _ = collect(reference, bodies, blobs)
    assert result['status'] == 'UNKNOWN'
    assert verdict(result, reference)[0] == 'UNKNOWN'


def test_later_missing_child_keeps_first_child_cve():
    reference, bodies, blobs, first, second = index_fixture()
    del blobs[next(key for key in blobs if key.endswith('/manifests/' + second))]
    result, _, _ = collect(reference, bodies, blobs, hit=True)
    assert result['status'] == 'FAIL', result
    assert result['complete'] is False
    assert verdict(result, reference)[0] == 'FAIL'
    record = result['rows'][0]['vulnerability_record']
    assert record['findings'][0]['image_digest'] == first
    assert record['graph']['complete'] is False
    from peaso.image_findings import build_report
    table = build_report(result['observations'], selected=True)
    assert table['coverage'] == 'UNKNOWN' and table['rows'][0]['image_digest'] == first


def test_stale_database_never_yields_clean_pass():
    reference, bodies, blobs, _, _ = index_fixture()
    result, _, _ = collect(reference, bodies, blobs, fresh=False)
    assert result['status'] == 'UNKNOWN'
    assert verdict(result, reference)[0] == 'UNKNOWN'


def test_docker_list_native_to_consumer():
    reference, bodies, blobs, _, _ = index_fixture(media_type=oci.DOCKER_LIST)
    result, _, _ = collect(reference, bodies, blobs)
    assert result['status'] == 'PASS'
    assert verdict(result, reference)[0] == 'PASS'


def test_incomplete_first_scan_does_not_hide_second_child_cve():
    reference, bodies, blobs, _, second = index_fixture()
    wire = fixture.transport()
    def mixed(identity, manifest, config, layers, **kwargs):
        kwargs['native_verifier']()
        second_child = identity['manifest_digest'] == second
        findings = []
        if second_child:
            findings = [{'vulnerability_id': 'CVE-2026-12345', 'severity': 'HIGH',
                'package_types': ['alpine'], 'package': 'fixture-package', 'version': '1.0',
                'fixed_in': ['1.1'], 'fix_status': 'fixed', 'classes': ['os-pkgs'],
                'image_digest': second}]
        return {'image': identity, 'status': 'FAIL' if findings else 'UNKNOWN',
            'complete': False, 'scan_complete': second_child,
            'coverage_status': 'UNKNOWN', 'database': {'fresh': second_child},
            'findings': findings}
    result = runtime.collect_selected(wire, scope=fixture.SCOPE, targets=[reference],
        metadata_session=fixture.MetadataSession(bodies), image_session=fixture.ImageSession(blobs),
        runner=mixed, db_cache='trusted-offline-cache')
    assert result['status'] == 'FAIL'
    assert verdict(result, reference)[0] == 'FAIL'
    assert result['rows'][0]['vulnerability_record']['findings'][0]['image_digest'] == second
    from peaso.image_findings import build_report
    table = build_report(result['observations'], selected=True)
    assert table['coverage'] == 'UNKNOWN' and table['rows'][0]['image_digest'] == second


def test_metadata_drift_after_scanning_disqualifies_child_findings():
    reference, bodies, blobs, _, _ = index_fixture()
    class Drift(fixture.MetadataSession):
        def request(self, method, url, **kwargs):
            if len(self.calls) == 3:
                self.bodies[source.requests_for(reference, fixture.SCOPE)[1][0]]['updateTime'] = '2026-10-21T10:00:00Z'
            return super().request(method, url, **kwargs)
    result = runtime.collect_selected(fixture.transport(), scope=fixture.SCOPE,
        targets=[reference], metadata_session=Drift(deepcopy(bodies)),
        image_session=fixture.ImageSession(blobs), runner=runner(hit=True),
        db_cache='trusted-offline-cache')
    assert result['status'] == 'UNKNOWN'
    assert verdict(result, reference)[0] == 'UNKNOWN'


def test_foreign_native_metadata_and_disabled_zero_io():
    reference, bodies, blobs, _, _ = index_fixture()
    invalid = deepcopy(bodies)
    invalid[source.requests_for(reference, fixture.SCOPE)[0][0]]['projectId'] = 'foreign'
    result, _, image = collect(reference, invalid, blobs)
    assert result['status'] == 'UNKNOWN' and not image.calls
    assert source.collect_native(object(), scope=fixture.SCOPE, selectors=[reference],
        enabled=False)['rows'] == []
