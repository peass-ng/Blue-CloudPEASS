"""Verified later GCP image files remain observable after one incomplete scan."""
import io
import json
import tarfile
from urllib.parse import quote

import pytest

from test_gcp_image_stream_inspection import (image, run, index, REPO, REPOSITORIES,
    PROJECTS, SCOPE, reviewed_predicate)
from test_gcp_image_stream_reader import digest
from peaso.collectors import gcp_image_stream_inspection_20261021 as inspection


def two_files(first_payload=b'\0\x01binary'):
    row, blobs = image(body=b'placeholder')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in (('app/binary.dat', first_payload),
                              ('app/credential.txt', b'later verified secret')):
            item = tarfile.TarInfo(name)
            item.size = len(payload)
            archive.addfile(item, io.BytesIO(payload))
    layer = output.getvalue()
    manifest = json.loads(blobs[row['digest']])
    config = json.loads(blobs[manifest['config']['digest']])
    config['rootfs']['diff_ids'] = [digest(layer)]
    config_raw = json.dumps(config, separators=(',', ':')).encode()
    manifest['config'].update(digest=digest(config_raw), size=len(config_raw))
    manifest['layers'][0].update(digest=digest(layer), size=len(layer))
    raw = json.dumps(manifest, separators=(',', ':')).encode()
    parent = digest(raw)
    row.update(digest=parent,
        uri='https://us-central1-docker.pkg.dev/review/images/app@' + parent,
        name=REPO + '/dockerImages/' + quote('app@' + parent, safe=''))
    return row, {digest(value): value for value in (raw, config_raw, layer)}


@pytest.mark.parametrize('incomplete', ['first_file', 'config', 'nested'])
def test_later_file_secret_survives_an_incomplete_detector(monkeypatch, incomplete):
    def scan(data, path, timeout, **kwargs):
        is_incomplete = (incomplete == 'first_file' and path == 'member-1') or (
            incomplete == 'config' and path == 'image-config.json')
        leaks = [{'fingerprint': 'a' * 64,
            'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
            'locations': [{'path': path, 'line': 1}]}] if path == 'member-2' else []
        return {'complete': not is_incomplete, 'engines': [
            {'engine': 'kingfisher', 'status': 'complete',
             'version': inspection.native.KINGFISHER_VERSION},
            {'engine': 'trufflehog', 'status': 'complete',
             'version': inspection.native.TRUFFLEHOG_VERSION}], 'leaks': leaks}
    monkeypatch.setattr(inspection.native, 'scan_content', scan)
    row, blobs = two_files(b'PK\x03\x04nested archive' if incomplete == 'nested'
                           else b'\0\x01binary')
    content, _, _ = run(row, blobs)
    row[inspection.native.MARKER] = content
    assert content['status'] == 'partial' and content['complete'] is False
    assert any(location['path'] == 'member-2' for leak in content['leaks']
               for location in leak['locations'])
    assert reviewed_predicate().evaluate(row, index(row))[0] == 'FAIL'


def test_typed_cancellation_propagates_through_image_and_enricher():
    class Cancelled(Exception):
        error = {'code': 'cancelled'}
    row, _ = two_files()
    class Reader:
        request_ids = []
        def get(self, *args, **kwargs):
            raise Cancelled()
        def close(self):
            pass
    with pytest.raises(Cancelled):
        inspection.inspect_image(row, SCOPE, REPOSITORIES, PROJECTS, Reader())
    collector = type('Collector', (), {'options': {'content_secret_scans': True,
        '_content_secret_scan_kinds': ['artifact_image'],
        'selected_artifact_images': [row['uri'].removeprefix('https://')]},
        'scopes': [SCOPE], 'transport': object(),
        'collections': {('artifact_image', SCOPE): {'status': 'collected', 'items': [row]},
            ('artifact_repository', SCOPE): {'status': 'collected', 'items': REPOSITORIES},
            ('project', SCOPE): {'status': 'collected', 'items': PROJECTS}}})()
    with pytest.raises(Cancelled):
        inspection.enrich(collector, reader_factory=lambda _: Reader())
