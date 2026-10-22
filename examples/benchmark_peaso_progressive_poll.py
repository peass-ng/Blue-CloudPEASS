"""Full watcher replay against retained report/snapshot files; no cloud or AI calls.

Poll waits are omitted to measure work only. Real FileArtifacts reads and JSON
parsing run at each iteration. Already completed sections are represented as persisted stage results. Temporary
private artifacts are removed; only timings, counts and hashes are printed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace

from peaso.storage.artifacts import FileArtifacts


def replay(module_path, report, snapshot, polls, enabled):
    spec = importlib.util.spec_from_file_location('peaso._progressive_benchmark', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    metrics = {'artifact_reads': 0, 'artifact_bytes_read': 0, 'job_polls': 0,
               'stage_claims': 0, 'stage_result_reads': 0, 'final_analyzer_runs': 0}
    class Artifacts(FileArtifacts):
        def get(self, tenant, reference):
            metrics['artifact_reads'] += 1
            metrics['artifact_bytes_read'] += (self.root/reference).stat().st_size
            return super().get(tenant, reference)
    class Store:
        def job(self, tenant, ident):
            metrics['job_polls'] += 1
            if metrics['job_polls'] > polls and row['status'] == 'collecting':
                row['status'] = 'collected'
            return dict(row)
        def stage_results(self, *args):
            metrics['stage_result_reads'] += 1
            return {stage: {'data_revision': value.get('data_revision')}
                    for stage, value in report['publication']['sections'].items()}
        def claim_stage(self, *args):
            metrics['stage_claims'] += 1
            raise AssertionError('Completed stage results must be reused')
    class Stopper:
        def is_set(self): return False
        def wait(self, seconds): pass
    with tempfile.TemporaryDirectory(prefix='peaso-watcher-private-') as folder:
        artifacts = Artifacts(Path(folder))
        report_ref = artifacts.put('benchmark', 'b'*32, 'report', report)
        snapshot_ref = artifacts.put('benchmark', 'b'*32, 'snapshot', snapshot)
        manifest_ref = artifacts.put('benchmark', 'b'*32, 'manifest', {
            'bundle_version': 1, 'report_json': report_ref,
            'summary': {key: value for key, value in report.items() if key not in {
                'resources', 'findings', 'coverage', 'graphs', 'snapshot', 'check_frameworks',
                'check_meta', 'check_meta_encoding', 'remediation_templates'}}})
        row = {'status': 'collecting', 'deadline': time.time()+600,
               'partial_report': manifest_ref, 'partial_snapshot': snapshot_ref,
               'data': json.dumps({'ai_enabled': enabled})}
        def final(*args):
            metrics['final_analyzer_runs'] += 1
            row['status'] = 'completed'
        worker = SimpleNamespace(role='analyzer', store=Store(), artifacts=artifacts,
            stopping=Stopper(), settings=SimpleNamespace(lease_seconds=30), run_once=final)
        began, cpu = time.perf_counter(), time.process_time()
        status = module.run_progressive(worker, 'benchmark', 'b'*32)
        metrics.update(wall_seconds=time.perf_counter()-began,
            cpu_seconds=time.process_time()-cpu, status=status, ai_enabled=enabled)
    assert metrics['final_analyzer_runs'] == 1 and status == 'completed'
    return metrics


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--polls', type=int, default=40)
    args = parser.parse_args()
    report_bytes, snapshot_bytes = args.report.read_bytes(), args.snapshot.read_bytes()
    report, snapshot = json.loads(report_bytes), json.loads(snapshot_bytes)
    assert report['publication']['state'] == 'partial'
    outputs = []
    for enabled in (True, False):
        before = replay(args.baseline, report, snapshot, args.polls, enabled)
        after = replay(args.candidate, report, snapshot, args.polls, enabled)
        assert before['job_polls'] == after['job_polls']
        assert before['stage_claims'] == after['stage_claims'] == 0
        outputs.append({'before': before, 'after': after})
    print(json.dumps({'polls': args.polls, 'results': outputs, 'cloud_calls': 0,
        'report_input_sha256': hashlib.sha256(report_bytes).hexdigest(),
        'snapshot_input_sha256': hashlib.sha256(snapshot_bytes).hexdigest()}, indent=2))
