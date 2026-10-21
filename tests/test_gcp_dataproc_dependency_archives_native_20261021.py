import ast
import importlib.util
from copy import deepcopy
import hashlib
import http.client
import io
import json
import logging
import os
from pathlib import Path
import re
import struct
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from urllib.parse import quote, urlsplit
from uuid import uuid4
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
CAND = ROOT
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.secret_evidence import scan_with_source, target_source

SOURCE = CAND / 'peaso/collectors/gcp_dataproc_referenced_source_secret_indicators.py'
CHECK = CAND / 'peaso/checks/gcp_dataproc_referenced_source_secret_review_20261020.py'
OBJECT = ROOT / 'peaso/collectors/gcp_selected_object_secret_indicators.py'
ZIP = ROOT / 'peaso/collectors/aws_package_content_indicators.py'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
TARGET = dict(profile='job', resource='projects/myproject1/regions/us-central1/jobs/job-1',
              field='pysparkJob.pythonFileUris[1]', bucket='owned-bucket',
              object='deps/helpers.zip', generation='17')
UUID = '12345678-1234-1234-1234-123456789abc'


from peaso.collectors import gcp_dataproc_referenced_source_secret_indicators as source_reader
from peaso.checks import gcp_dataproc_referenced_source_secret_review_20261020 as source_check


def native():
    return source_reader, source_check._evaluate


@pytest.fixture(autouse=True)
def restore_native_session(monkeypatch):
    original = source_reader.git._session
    yield
    monkeypatch.setattr(source_reader.git, '_session', original)


class Raw:
    def __init__(self, body): self.body = io.BytesIO(body)
    def read(self, n, decode_content=False): return self.body.read(n)


class Response:
    history = []
    def __init__(self, url, status, body, headers):
        self.url, self.status_code, self.raw, self.headers = url, status, Raw(body), headers
        self.closed = False
    def close(self): self.closed = True


class Session:
    def __init__(self, fixture): self.fixture, self.closed = fixture, False
    def request(self, method, url, *, params, **kw):
        import requests
        route = requests.Request(method, url, params=params).prepare().url
        status, body, headers = self.fixture(url, params)
        self.response = Response(route, status, body, headers)
        return self.response
    def close(self): self.closed = True


def archive(files, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression) as z:
        for name, content in files:
            z.writestr(name, content)
    return buf.getvalue()


def capture(payload, *, target=TARGET, denied=False, drift=False, gcs_drift=False, truncated=False,
            cancelled=False, content_type='application/zip'):
    src, evaluate = native()
    sessions = []
    count = {'reference': 0, 'metadata': 0}
    resource = target['resource']
    job = dict(reference={'projectId': 'myproject1', 'jobId': resource.split('/')[-1]},
               jobUuid=UUID, pysparkJob={'mainPythonFileUri': 'gs://owned-bucket/main.py',
               'pythonFileUris': ['gs://owned-bucket/first.py',
                                  'gs://' + target['bucket'] + '/' + target['object']]})
    def fixture(url, params):
        if denied and 'dataproc.googleapis.com' in url:
            return 403, b'{}', {'Content-Length': '2', 'Content-Type': 'application/json'}
        if 'cloudresourcemanager.googleapis.com' in url:
            data = {'name': 'projects/12345', 'projectId': 'myproject1', 'state': 'ACTIVE'}
        elif 'dataproc.googleapis.com' in url:
            count['reference'] += 1
            data = deepcopy(job)
            if drift and count['reference'] == 2:
                data['jobUuid'] = '12345678-1234-1234-1234-123456789abd'
        elif url.endswith('/b/owned-bucket'):
            data = {'name': 'owned-bucket', 'projectNumber': '12345'}
        elif params.get('alt') == 'media':
            body = payload[:-1] if truncated else payload
            return 200, body, {'Content-Length': str(len(payload)), 'Content-Type': content_type,
                               'X-Goog-Generation': target['generation']}
        else:
            count['metadata'] += 1
            data = {'bucket': target['bucket'], 'name': target['object'],
                    'generation': '18' if gcs_drift and count['metadata'] == 2 else target['generation'],
                    'size': str(len(payload)),
                    'contentType': content_type}
        body = json.dumps(data, separators=(',', ':')).encode()
        return 200, body, {'Content-Length': str(len(body)), 'Content-Type': 'application/json'}
    def session():
        s = Session(fixture); sessions.append(s); return s
    src.git._session = session
    calls = {'credentials': 0, 'cancel': 0}
    def credentials():
        calls['credentials'] += 1
        return {'Authorization': 'Bearer offline-token'}
    def check_cancelled():
        calls['cancel'] += 1
        if cancelled: raise src.Incomplete('cancelled')
    transport = SimpleNamespace(lock=threading.RLock(), calls=0, max_calls=None,
        credentials=SimpleNamespace(headers=credentials), options={}, timeout=10,
        deadline=None, deadline_seconds=None, started=time.monotonic(),
        check_cancelled=check_cancelled)
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': ['dataproc_selected_job_source'],
            'selected_dataproc_referenced_sources': [target]}
    collector = SimpleNamespace(options=opts, scopes=['projects/myproject1'], transport=transport)
    items = src.collect_sources(collector, 'projects/myproject1', 'job')
    metadata = src.selection_metadata(collector)
    ident = src.identity(target)
    index = {'context': {'provider': 'gcp', 'scope': 'projects/myproject1', 'metadata': metadata},
             'collections': {'dataproc_selected_job_source': [{'scope': 'projects/myproject1',
               'status': 'collected', 'items': items,
               'source_requests': items[0][src.MARKER]['source_requests'] if items else []}]}}
    status, evidence = evaluate(items[0], index, 'job') if items else ('UNKNOWN', {})
    return src, status, evidence, items[0], metadata, calls, sessions


def test_selected_zip_and_egg_real_detectors():
    for suffix in ('.zip', '.egg'):
        target = {**TARGET, 'object': 'deps/helpers' + suffix}
        payload = archive([('pkg/helper.py', 'TOKEN = "' + TOKEN + '"\n')])
        src, status, evidence, item, meta, _, sessions = capture(payload, target=target)
        assert status == 'FAIL', (status, item[src.MARKER]['reason'])
        assert len(item[src.MARKER]['leaks']) >= 1
        assert len(item[src.MARKER]['parts'][0]['engines']) == 2
        assert len(item[src.MARKER]['source_requests']) == 9
        assert all(s.closed and s.response.closed for s in sessions)
        assert TOKEN not in json.dumps([item, meta, evidence])


def test_clean_and_incomplete_archives():
    clean = archive([('pkg/helper.py', 'print("hello")\n')])
    _, status, _, _, _, _, _ = capture(clean, content_type='application/octet-stream')
    assert status == 'PASS'
    stored = archive([('pkg/helper.py', 'print("hello")\n')], zipfile.ZIP_STORED)
    corrupt = bytearray(stored)
    assert stored.find(b'print(') > 0
    corrupt[stored.find(b'print(')] ^= 1
    for payload in (archive([('../escape.py', 'print(1)')]),
                    archive([('pkg/tool.pyc', b'\0\x01')]),
                    clean[:-3], bytes(corrupt)):
        _, status, _, _, _, _, _ = capture(payload)
        assert status == 'UNKNOWN'


def test_partial_positive_retained():
    payload = archive([('pkg/a.py', 'TOKEN = "' + TOKEN + '"\n'),
                       ('pkg/b.pyc', b'\0\x01')])
    src, status, evidence, item, _, _, _ = capture(payload)
    assert status == 'FAIL', (status, item[src.MARKER])
    assert item[src.MARKER]['complete'] is False
    assert evidence['secret_leaks']


def test_one_detector_positive_other_unavailable(monkeypatch):
    import peaso.secret_scanning as scanning
    def unavailable(*args, **kwargs): raise RuntimeError('offline detector unavailable')
    monkeypatch.setattr(scanning, '_scan_trufflehog', unavailable)
    payload = archive([('pkg/helper.py', 'TOKEN = "' + TOKEN + '"\n')])
    src, status, evidence, item, _, _, _ = capture(payload)
    assert status == 'FAIL'
    assert item[src.MARKER]['complete'] is False
    assert evidence['secret_leaks']


def test_native_denied_drift_truncated_and_cancelled():
    payload = archive([('pkg/helper.py', 'print(1)\n')])
    for flags in ({'denied': True}, {'drift': True}, {'gcs_drift': True},
                  {'truncated': True}, {'cancelled': True}):
        src, status, _, item, _, calls, _ = capture(payload, **flags)
        assert status == 'UNKNOWN', (flags, status)
        assert item[src.MARKER]['complete'] is False
        if flags.get('cancelled'):
            assert calls['credentials'] == 0


def test_foreign_and_malformed_selection_and_default_off():
    src, _ = native()
    for target in ({**TARGET, 'object': 'deps/helpers.jar'},
                   {**TARGET, 'field': 'pysparkJob.pythonFileUris[100]'},
                   {**TARGET, 'resource': 'projects/otherproj1/regions/us-central1/jobs/job-1'}):
        if target['resource'] != TARGET['resource']:
            with pytest.raises(src.Incomplete):
                src.selected_targets({'content_secret_scans': True,
                    '_content_secret_scan_kinds': ['dataproc_selected_job_source'],
                    'selected_dataproc_referenced_sources': [target]}, ['projects/myproject1'])
        else:
            with pytest.raises(src.Incomplete): src.parse(target)
    assert src.selected_targets({'content_secret_scans': False}, ['projects/myproject1']) == []
    assert src.enabled({'content_secret_scans': False}, 'job') is False
    blocked = SimpleNamespace(options={'content_secret_scans': False}, scopes=['projects/myproject1'],
                              transport=SimpleNamespace(credentials=SimpleNamespace(
                                  headers=lambda: pytest.fail('default-off credentials read'))))
    assert src.collect_sources(blocked, 'projects/myproject1', 'job') == []
    foreign = {**TARGET, 'bucket': 'foreign-bucket'}
    payload = archive([('pkg/helper.py', 'print(1)\n')])
    _, status, _, _, _, _, _ = capture(payload, target=foreign)
    assert status == 'UNKNOWN'


def test_pure_api_selector_parity_and_cold_import():
    pure_path = CAND / 'peaso/dataproc_source_selection.py'
    spec = importlib.util.spec_from_file_location('dataproc_source_selection', pure_path)
    pure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pure)
    src, _ = native()
    cases = [TARGET, {**TARGET, 'object': 'deps/helpers.egg'},
             {**TARGET, 'object': 'deps/helpers.py'},
             {**TARGET, 'object': 'deps/helpers.jar'},
             {**TARGET, 'field': 'pysparkJob.pythonFileUris[100]'},
             {**TARGET, 'generation': '0'},
             {**TARGET, 'bucket': 'foreign-bucket'}]
    for target in cases:
        try: expected = src.parse(target)
        except src.Incomplete: expected = None
        try: actual = pure.parse(target)
        except ValueError: actual = None
        assert actual == expected
    for rows in ([TARGET], [TARGET, TARGET], [], [{**TARGET, 'resource':
                  'projects/otherproj1/regions/us-central1/jobs/job-1'}]):
        opts = {'content_secret_scans': False, pure.OPTION: rows}
        try: expected = src.selected_targets(opts, ['projects/myproject1'])
        except src.Incomplete: expected = None
        try: actual = pure.selected_targets(opts, ['projects/myproject1'])
        except ValueError: actual = None
        assert actual == expected
    code = '''import importlib.util,sys
p=sys.argv[1]
s=importlib.util.spec_from_file_location("pure",p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
assert m.parse({"profile":"job","resource":"projects/myproject1/regions/us-central1/jobs/job-1","field":"pysparkJob.pythonFileUris[0]","bucket":"owned-bucket","object":"deps/helper.egg","generation":"17"})=="projects/myproject1"
assert not any(x.startswith(("peaso.collectors","peaso.checks","peaso.engine","peaso.analysis")) for x in sys.modules)
'''
    done = subprocess.run([sys.executable, '-I', '-c', code, str(pure_path)],
                          capture_output=True, text=True, timeout=5)
    assert done.returncode == 0, done.stderr
