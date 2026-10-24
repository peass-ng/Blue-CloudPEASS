"""Slow report publication cannot block durable native collection batches."""
import threading
from types import SimpleNamespace
import pytest
from peaso import worker
from peaso.storage import reports


def test_raw_ack_during_report_upload_preserves_private_order(monkeypatch):
    started, release, raw_done = (threading.Event() for _ in range(3))
    capture = SimpleNamespace(generation=1)
    private_versions, acknowledged, errors = [], [], []
    class Artifacts:
        def put_secret_evidence(self, tenant, ident, document):
            private_versions.append(document['generation'])
        def put(self, tenant, ident, kind, value):
            assert private_versions[-1] >= value['required_private']
            return 'snapshot-' + str(value['required_private'])
    class Pipe:
        waiting = None
        def send(self, value):
            assert self.waiting is None, 'checkpoint exchanges interleaved'
            self.waiting = value[1]
            assert private_versions[-1] >= self.waiting['sequence']
        def recv(self):
            event, self.waiting = self.waiting, None
            acknowledged.append(event)
            if event['report_ref'] is None: raw_done.set()
            return ('__checkpoint_ack__', event['sequence'], True)
    def publish(*args):
        started.set()
        assert release.wait(3)
        return 'full-report'
    monkeypatch.setattr(reports, 'publish_report', publish)
    private = SimpleNamespace(document=lambda capture: {'generation': capture.generation})
    publish_checkpoint = worker._collector_checkpoint_publisher(
        Artifacts(), object(), 'tenant', 'scan', capture, private, Pipe())
    def full():
        try: publish_checkpoint({'required_private':1}, {}, 1)
        except BaseException as exc: errors.append(exc)
    thread = threading.Thread(target=full);thread.start()
    try:
        assert started.wait(2)
        capture.generation = 2
        publish_checkpoint({'required_private':2,'collections':[{'type':'pod','scope':'default'}]}, None, 2)
        assert raw_done.is_set() and thread.is_alive()
    finally:
        release.set();thread.join(3)
    assert not errors and not thread.is_alive()
    assert [event['sequence'] for event in acknowledged] == [2,1]
    assert private_versions == sorted(private_versions) == [1,2,2]


@pytest.mark.parametrize('report', [None, {}])
def test_private_commit_failure_never_exposes_public_artifact(report):
    calls = []
    class Artifacts:
        def put_secret_evidence(self,*args): raise OSError('private upload failed')
        def put(self,*args): calls.append('public')
    private = SimpleNamespace(document=lambda capture: {})
    publish = worker._collector_checkpoint_publisher(Artifacts(),object(),'tenant','scan',None,private,None)
    with pytest.raises(OSError,match='private upload failed'):
        publish({},report,1)
    assert not calls
