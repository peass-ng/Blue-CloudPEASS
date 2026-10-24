"""Publish native results before waiting for independently running AI stages."""
from peaso import engine, worker
from peaso.ai import pipeline, network
from peaso.storage.artifacts import FileArtifacts
from peaso.storage import reports, cost
from peaso.snapshot import make_snapshot


def test_analyzer_native_publication_precedes_fresh_stage_handoff(tmp_path, monkeypatch):
    artifacts = FileArtifacts(tmp_path)
    snapshot = make_snapshot('k8s', ['default'], [])
    reference = artifacts.put('tenant', 'a' * 32, 'snapshot', snapshot)
    events = []
    refreshed = {'network': {'data_revision': 7, 'result_ref': 'durable-network'}}
    calls = []

    def evaluate(*args, **kwargs):
        calls.append('evaluate')
        return {'provider': 'k8s', 'snapshot_id': snapshot['snapshot_id'],
                'findings': [], 'stats': {}, 'graphs': {}}

    def publish(artifacts, tenant, ident, report, native):
        phase = report['publication']['phase']
        events.append(phase)
        return 'native-report' if phase == 'analyzing' else 'final-report'

    def review(*args, **kwargs):
        assert events == ['analyzing', 'stage_results_requested']
        assert kwargs['reused_stages'] == refreshed
        events.append('review')
        return {'status': 'completed', 'network': {'findings': []}}

    class Pipe:
        sent = []
        def send(self, value):
            self.sent.append(value)
            if value[0] == '__stage_results__':
                assert events == ['analyzing']
                events.append('stage_results_requested')
        def recv(self):
            value = self.sent[-1]
            if value[0] == '__checkpoint__':
                return ('__checkpoint_ack__', value[1]['sequence'], True)
            assert value[0] == '__stage_results__'
            return ('__stage_results__', refreshed)
        def close(self): pass

    monkeypatch.setattr(worker.os, 'dup2', lambda *_: None)
    monkeypatch.setattr(worker.signal, 'signal', lambda *_: None)
    monkeypatch.setattr(engine, 'evaluate_snapshot', evaluate)
    monkeypatch.setattr(reports, 'publish_report', publish)
    monkeypatch.setattr(cost, 'runtime_estimate', lambda timeline: {})
    monkeypatch.setattr(worker, '_reusable_stages', lambda a,t,s,r: r)
    monkeypatch.setattr(pipeline, 'review_scan', review)
    monkeypatch.setattr(network, 'with_findings', lambda report, findings: report)
    pipe = Pipe()
    request = {'artifact_config': {'mode': 'file', 'root': str(tmp_path)},
        'tenant_id': 'tenant', 'scan_id': 'a' * 32, 'snapshot_ref': reference,
        'selectors': {}, 'timeline': {}, 'related': [],
        'stage_results': {'old': {}}, 'refresh_stage_results': True}
    worker._process('analyzer', request, pipe)
    assert calls == ['evaluate']
    assert events == ['analyzing', 'stage_results_requested', 'review', 'completed']
    assert pipe.sent[-1] == (True, 'final-report')
