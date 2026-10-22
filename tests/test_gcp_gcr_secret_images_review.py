"""Native GCR DockerImage identity and immutable byte inspection; no live calls."""
import base64
import json
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from peaso.collectors import gcp
from peaso.collectors import gcp_image_secret_indicators as projection
from peaso.collectors import gcp_image_stream_inspection_20261021 as stream
from peaso.collectors.gcp_registry_image_uri import GCR_REPOSITORIES, parse
from tests.test_gcp_image_secret_review_20261019 import (image, check, SCOPE, PROJECTS, TOKEN,
                                                        clean, real, isolate)  # noqa: F401


class Session:
    def __init__(self, bodies, prefix):
        self.bodies, self.prefix, self.calls, self.closed = bodies, prefix, [], False

    def request(self, method, url, **kwargs):
        assert method == 'GET' and url.startswith(self.prefix)
        assert kwargs['allow_redirects'] is False and kwargs['stream'] is True
        assert base64.b64decode(kwargs['headers']['Authorization'][6:]) == b'oauth2accesstoken:fixture-access-token'
        self.calls.append(url)
        raw = self.bodies[url]
        return SimpleNamespace(status_code=200, url=url, history=[],
            headers={'Content-Length': str(len(raw))},
            iter_content=lambda chunk_size: iter([raw]), close=lambda: None)

    def close(self): self.closed = True


def collected(monkeypatch, host, value='production', wrong_repo=False, extra_format=None):
    original, bodies = image(value)
    location, repo_id = GCR_REPOSITORIES[host]
    repo = f'{SCOPE}/locations/{location}/repositories/{repo_id}'
    uri = 'https://' + host + '/review/team/app@' + original['digest']
    row = {**original, 'uri': uri, 'repository': repo,
           'name': repo + '/dockerImages/' + quote('team/app@' + original['digest'], safe='')}
    old_base = 'https://us-central1-docker.pkg.dev/v2/review/images/app/'
    new_base = 'https://' + host + '/v2/review/team/app/'
    binary = Session({url.replace(old_base, new_base): raw for url, raw in bodies.items()}, new_base)
    reader_type = stream.Reader
    monkeypatch.setattr(stream, 'Reader', lambda transport: reader_type(transport, session=binary))
    calls = []

    def request(method, url, **kwargs):
        assert method == 'GET'
        calls.append(url)
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            data = {**PROJECTS[0], 'state': 'ACTIVE'}
        elif url == 'https://compute.googleapis.com/compute/v1/' + SCOPE:
            data = {'name': 'review', 'id': '10001', 'commonInstanceMetadata': {'items': []}}
        elif url.endswith('/locations/' + location + '/repositories'):
            data = {'repositories': [{'name': repo, 'format': 'DOCKER'}]}
            if extra_format:
                data['repositories'].append({'name': f'{SCOPE}/locations/{location}/repositories/packages',
                                              'format': extra_format})
        elif url == 'https://artifactregistry.googleapis.com/v1/' + repo + '/dockerImages':
            data = {'dockerImages': [{'name': row['name'].replace('/dockerImages/', '-other/dockerImages/')
                                     if wrong_repo else row['name'], 'uri': uri.removeprefix('https://')}]}
        elif url.endswith(':getIamPolicy'):
            data = {'bindings': []}
        else:
            raise AssertionError('Unexpected native URL: ' + url)
        return SimpleNamespace(status_code=200, headers={}, content=json.dumps(data).encode(),
                               json=lambda: deepcopy(data))

    options = {'content_secret_scans': True, '_content_secret_scan_kinds': ['artifact_image'],
               'selected_artifact_images': [uri.removeprefix('https://')],
               'inventories': ['artifact_image', 'artifact_repository', 'project'],
               'artifactregistry_locations': [location], 'include_inherited': False,
               'metrics_scopes': False, 'concurrency': 1}
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization': 'Bearer fixture-access-token'},
                                             close=lambda: None), options)
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    snapshot = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': options},
        requirements=['artifact_image', 'artifact_repository', 'project'], transport=transport).collect()
    return snapshot, binary, calls


@pytest.mark.parametrize('host', sorted(GCR_REPOSITORIES))
def test_native_gcr_repository_identity_and_all_layers_survive_installed_pipeline(monkeypatch, clean, host):
    snapshot, binary, _ = collected(monkeypatch, host)
    envelope = next(row for row in snapshot['collections'] if row['type'] == 'artifact_image')
    assert envelope['status'] == 'collected', envelope
    row, = envelope['items']
    index = {'context': {'provider': 'gcp', 'scope': SCOPE},
             'collections': {kind: [e for e in snapshot['collections'] if e['type'] == kind]
                 for kind in ['artifact_image', 'artifact_repository', 'project']}}
    assert check.evaluate(row, index)[0] == 'PASS', row
    from peaso.engine import evaluate_snapshot
    findings = evaluate_snapshot(snapshot, checks=[projection.CHECK_ID])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'PASS'
    assert len(binary.calls) == 4 and binary.closed
    assert row['uri'].startswith('https://' + host + '/')
    assert projection.normalize_selected([row['uri'].removeprefix('https://')], SCOPE) == [row['uri']]
    assert not any('-docker.pkg.dev' in url for url in binary.calls)  # No inferred alias substitution.


def test_gcr_real_offline_detectors_find_one_redacted_leak(monkeypatch, real):
    snapshot, binary, _ = collected(monkeypatch, 'gcr.io', TOKEN)
    row, = next(e['items'] for e in snapshot['collections'] if e['type'] == 'artifact_image')
    marker = row[projection.MARKER]
    assert marker['complete'] is True and len(marker['leaks']) == 1
    assert {d['engine'] for d in marker['leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in repr(snapshot)
    assert len(binary.calls) == 4
    from peaso.engine import evaluate_snapshot
    findings = evaluate_snapshot(snapshot, checks=[projection.CHECK_ID])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'FAIL'
    assert len(findings[0]['evidence']['secret_leaks']) == 1


def test_foreign_native_repository_binding_stops_before_any_content_read(monkeypatch, clean):
    snapshot, binary, _ = collected(monkeypatch, 'eu.gcr.io', wrong_repo=True)
    envelope = next(row for row in snapshot['collections'] if row['type'] == 'artifact_image')
    assert envelope['status'] not in ('collected', 'empty')
    assert not binary.calls


@pytest.mark.parametrize('format', ['PYTHON', 'NPM', 'MAVEN', 'RUBY', 'CONDA'])
def test_non_docker_siblings_do_not_invalidate_selected_native_image_inventory(monkeypatch, clean, format):
    snapshot, binary, calls = collected(monkeypatch, 'gcr.io', extra_format=format)
    from peaso.engine import evaluate_snapshot
    findings = evaluate_snapshot(snapshot, checks=[projection.CHECK_ID])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'PASS', findings
    assert len(binary.calls) == 4
    assert not any('/repositories/packages/dockerImages' in url for url in calls)


def test_unknown_repository_format_remains_incomplete(monkeypatch, clean):
    snapshot, binary, _ = collected(monkeypatch, 'gcr.io', extra_format='FUTURE_IMAGE_FORMAT')
    from peaso.engine import evaluate_snapshot
    assert all(f['status'] == 'UNKNOWN' for f in evaluate_snapshot(snapshot,
        checks=[projection.CHECK_ID])['findings'])
    assert not binary.calls


@pytest.mark.parametrize('host', sorted(GCR_REPOSITORIES))
def test_gcr_scope_stays_native_project_bound(host):
    uri = host + '/foreign/team/app@sha256:' + 'a' * 64
    with pytest.raises(ValueError): projection.normalize_selected([uri], SCOPE)


@pytest.mark.parametrize('uri', ['mirror.gcr.io/review/app', 'gcr.io.external.test/review/app',
    'gcr.io:443/review/app', 'user@gcr.io/review/app', 'gcr.io/review/../app',
    'gcr.io/review/team//app', 'gcr.io/review/%2e%2e/app'])
def test_unknown_hosts_encoded_or_ambiguous_paths_are_rejected(uri):
    with pytest.raises(ValueError): parse(uri + '@sha256:' + 'a' * 64)
