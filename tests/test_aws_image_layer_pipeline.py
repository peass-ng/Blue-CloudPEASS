"""Layer overlap preserves native budgets, ordered evidence and scratch ownership."""
import hashlib
import importlib.util
from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest
from peaso.collectors import aws_image_vulnerability_native_20261021 as native
from peaso.collectors import aws_image_capture_20261022 as capture

spec = importlib.util.spec_from_file_location('peaso.collectors._layer_pipeline_test',
    Path(__file__).resolve().parents[1]/'peaso/collectors/aws_image_layer_pipeline_20261022.py')
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


@pytest.fixture
def fixture(monkeypatch, tmp_path):
    lock = threading.RLock()
    q = SimpleNamespace(_lock=lock, calls=0, max_calls=None, deadline=None, timeout=5,
                        check_deadline=lambda: None)
    state = dict(sdk_active=0, sdk_peak=0, transfers=0, peak=0, completed=[],
                 clients=0, active_at_return=None)
    bodies = [(f'layer-{i}\n'*100).encode() for i in range(6)]
    descs = [dict(digest='sha256:'+hashlib.sha256(body).hexdigest(), size=len(body))
             for body in bodies]
    by_digest = {desc['digest']: body for desc, body in zip(descs,bodies)}
    class Client:
        def get_download_url_for_layer(self, **args):
            with lock:
                state['sdk_active'] += 1
                state['sdk_peak'] = max(state['sdk_peak'], state['sdk_active'])
            time.sleep(.005)
            with lock: state['sdk_active'] -= 1
            return dict(ResponseMetadata={'HTTPStatusCode':200},
                layerDigest=args['layerDigest'], downloadUrl=args['layerDigest'])
        def close(self): pass
    def client(*args, **kwargs):
        with lock: state['clients'] += 1
        return Client()
    reader = native.Reader(q,SimpleNamespace(client=client),'123456789012','us-east-1')
    def download(requests, url, region, digest, size, path, *, check, end):
        with lock:
            state['transfers'] += 1
            state['peak'] = max(state['peak'], state['transfers'])
            requests.calls += 1
        try:
            check()
            # First layer deliberately finishes later; result/evidence order
            # must still follow the native manifest, not worker completion.
            for _ in range(12 if digest == descs[0]['digest'] else 3):
                time.sleep(.005)
                check()
            assert size == len(by_digest[digest])
            path.write_bytes(by_digest[digest]);path.chmod(0o600)
            with lock: state['completed'].append(digest)
            return path
        finally:
            with lock: state['transfers'] -= 1
    monkeypatch.setattr(native,'download_blob_path',download)
    return SimpleNamespace(reader=reader,requests=q,descs=descs,root=tmp_path,
                           state=state,bodies=bodies,download=download)


def run(f):
    return pipeline.download_layers(f.reader,'fixture',f.descs,f.root,'sha256:'+'a'*64)


def expected_ledger(f):
    return [entry for desc in f.descs for entry in (
        {'operation':'ecr:get_download_url_for_layer','status':'collected'},
        {'operation':'ecr:signed_layer_download','status':'collected',
         'digest':desc['digest'],'bytes':desc['size']})]


def test_bounded_overlap_preserves_manifest_bytes_and_exact_source_order(fixture):
    f=fixture
    paths=run(f)
    assert f.state['peak'] == 2 and f.state['sdk_peak'] == 1 and f.state['clients'] == 1
    assert f.state['completed'][0] != f.descs[0]['digest']
    assert [p.name for p in paths] == [f'layer-{i}.blob' for i in range(6)]
    assert [p.read_bytes() for p in paths] == f.bodies
    assert f.reader.ledger == expected_ledger(f)
    assert f.reader.calls == f.reader.target_calls == 6 and f.requests.calls == 12
    assert f.state['transfers'] == 0


@pytest.mark.parametrize('reason',['explicit_cap','target_budget','batch_budget','one_layer'])
def test_finite_admission_retains_serial_order(fixture,reason):
    f=fixture
    if reason == 'explicit_cap': f.requests.max_calls=100
    if reason == 'target_budget': f.reader.target_calls=native.MAX_CALLS-5
    if reason == 'batch_budget': f.reader.calls=f.reader.max_calls-5
    if reason == 'one_layer': f.descs=f.descs[:1];f.bodies=f.bodies[:1]
    if reason in ('target_budget','batch_budget'):
        with pytest.raises(ValueError,match='native_image_binding_unavailable'):run(f)
        assert f.reader.ledger == expected_ledger(f)[:10]
    else:
        assert len(run(f)) == len(f.descs)
        assert f.reader.ledger == expected_ledger(f)
    assert f.state['peak'] == 1 and f.state['transfers'] == 0


def test_failure_stops_new_work_joins_other_reader_before_return(fixture,monkeypatch):
    f=fixture;entered=threading.Barrier(2)
    def fail(requests,url,region,digest,size,path,*,check,end):
        entered.wait(timeout=3)
        if digest == f.descs[1]['digest']:
            raise RuntimeError('synthetic failed layer')
        # The other worker cooperates with pipeline cancellation. It must be
        # joined before its scratch-owning caller can delete this directory.
        with f.requests._lock:f.state['transfers'] += 1
        try:
            for _ in range(500):check();time.sleep(.002)
            pytest.fail('cancellation was not observed')
        finally:
            with f.requests._lock:f.state['transfers'] -= 1
    monkeypatch.setattr(native,'download_blob_path',fail)
    with pytest.raises(RuntimeError,match='synthetic failed layer'):run(f)
    assert f.state['transfers'] == 0
    assert f.reader.calls == 2
    assert [row['operation'] for row in f.reader.ledger] == ['ecr:get_download_url_for_layer']*2
    assert not list(f.root.iterdir())


def test_job_cancellation_keeps_original_exception_and_joins(fixture,monkeypatch):
    f=fixture
    class Cancelled(RuntimeError):code='collection_cancelled'
    def cancelled():raise Cancelled('synthetic cancelled')
    f.requests.check_deadline=cancelled
    with pytest.raises(Cancelled):run(f)
    assert f.state['transfers'] == 0 and f.reader.calls == 0 and not f.reader.ledger


def test_capture_reuses_original_authority_and_descriptor_without_redownload(fixture):
    f=fixture
    with capture.capture_scope(f.requests) as captured:
        first=run(f);calls=f.requests.calls
        second=run(f)
        assert first == second and len(captured.entries) == len(f.descs)
        assert f.requests.calls == calls == 12
        assert all(path.parent == captured.root for path in first)
        assert all(path.stat().st_mode & 0o077 == 0 for path in first)
        assert f.state['transfers'] == 0
    assert all(not path.exists() for path in first)


def test_empty_descriptor_list_keeps_serial_result(fixture):
    f=fixture;f.descs=[]
    assert run(f) == [] and f.requests.calls == 0 and not f.reader.ledger


def test_submit_failure_stops_and_joins_already_running_worker(fixture,monkeypatch):
    f=fixture;entered=threading.Event();checks=[]
    real=pipeline.ThreadPoolExecutor
    def wait_for_stop(requests,url,region,digest,size,path,*,check,end):
        entered.set()
        for _ in range(500):
            checks.append(1);check();time.sleep(.002)
        pytest.fail('started worker was not stopped')
    class FailingPool(real):
        def submit(self,*args,**kwargs):
            if getattr(self,'submitted',False):
                assert entered.wait(timeout=3)
                raise RuntimeError('synthetic submission failure')
            self.submitted=True
            return super().submit(*args,**kwargs)
    monkeypatch.setattr(native,'download_blob_path',wait_for_stop)
    monkeypatch.setattr(pipeline,'ThreadPoolExecutor',FailingPool)
    with pytest.raises(RuntimeError,match='synthetic submission failure'):run(f)
    assert 1<=len(checks)<100
    assert f.reader.calls==1 and not list(f.root.iterdir())
