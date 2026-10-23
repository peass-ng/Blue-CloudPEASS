"""Compare the whole hosted artifact write stage with encoded chunk reuse.

python -m examples.benchmark_peaso_encoded_publication --findings 50000

Both paths use bounded uploads, real JSON/gzip/KMS request policy, identical
report/Markdown/chunks/indexes/coverage/graphs and a final manifest barrier.
S3 is simulated with zero latency to expose CPU cost; no cloud calls are made.
Excludes evaluation, finding grouping, native expansion and Markdown generation.
"""
import argparse
import json
import statistics
import time

from examples.benchmark_peaso_publication import SimulatedS3, content_digest, synthetic_report
from peaso.reports import render_markdown
from peaso.storage.artifacts import S3Artifacts
from peaso.storage.reports import (_artifact_chunks, _prepared_findings, _put_chunk,
                                   CHUNK_BYTES, chunks, finding_summary)


def previous_writes(store, report, markdown):
    tenant, scan = 'benchmark', 'a' * 32
    manifest = {'report_json': store.put(tenant, scan, 'report', report),
                'report_markdown': store.put_text(tenant, scan, 'markdown', markdown),
                'finding_chunks': [], 'coverage_chunks': [], 'graphs': {}}
    # The previous publisher separately used default JSON encoding to decide
    # oversized detail placement, then encoded rows again for chunk sizing.
    # These synthetic rows are all ordinary inline findings.
    for finding in report['findings']:
        assert len(json.dumps(finding).encode()) <= CHUNK_BYTES
    for group in chunks(report['findings']):
        reference = store.put(tenant, scan, 'findings', {'items': group})
        index = store.put(tenant, scan, 'finding-index', {'items': [finding_summary(row) for row in group]})
        manifest['finding_chunks'].append({'reference': reference, 'index_reference': index})
    for group in chunks(report['coverage']):
        manifest['coverage_chunks'].append(store.put(tenant, scan, 'coverage', {'items': group}))
    for kind in ('network', 'iam', 'privesc'):
        graph = report['graphs'].get(kind, {'nodes': [], 'edges': []})
        manifest['graphs'][kind] = store.put(tenant, scan, 'graph-' + kind, graph)
    return store.put(tenant, scan, 'manifest', manifest)


def encoded_writes(store, report, markdown):
    tenant, scan = 'benchmark', 'a' * 32
    manifest = {'report_json': store.put(tenant, scan, 'report', report),
                'report_markdown': store.put_text(tenant, scan, 'markdown', markdown),
                'finding_chunks': [], 'coverage_chunks': [], 'graphs': {}}
    prepared = _prepared_findings(store, tenant, scan, report['findings'])
    for group, body in _artifact_chunks(store, prepared, preencoded=True):
        reference = _put_chunk(store, tenant, scan, 'findings', group, body)
        index = store.put(tenant, scan, 'finding-index', {'items': [finding_summary(row) for row in group]})
        manifest['finding_chunks'].append({'reference': reference, 'index_reference': index})
    for group, body in _artifact_chunks(store, report['coverage']):
        manifest['coverage_chunks'].append(_put_chunk(store, tenant, scan, 'coverage', group, body))
    for kind in ('network', 'iam', 'privesc'):
        graph = report['graphs'].get(kind, {'nodes': [], 'edges': []})
        manifest['graphs'][kind] = store.put(tenant, scan, 'graph-' + kind, graph)
    return store.put(tenant, scan, 'manifest', manifest)


def compare(findings=50000):
    report = synthetic_report(findings)
    original = json.dumps(report, sort_keys=True)
    markdown = render_markdown(report)
    results = {}
    for name, publish in (('baseline', previous_writes), ('optimized', encoded_writes)):
        seconds, fingerprints = [], []
        for _ in range(3):
            client = SimulatedS3(0)
            store = S3Artifacts('private', client=client, kms_key='fixture-kms')
            started = time.perf_counter()
            with store.batch() as writer:
                reference = publish(writer, report, markdown)
            seconds.append(round(time.perf_counter() - started, 6))
            assert list(client.objects)[-1] == 'artifacts/' + reference
            assert all(r['ServerSideEncryption'] == 'aws:kms' and r['SSEKMSKeyId'] == 'fixture-kms'
                       for r in client.objects.values())
            fingerprints.append(content_digest(client.objects))
        assert len(set(fingerprints)) == 1
        results[name] = {'seconds': seconds, 'artifact_count': len(client.objects), 'content_digest': fingerprints[0]}
    assert results['baseline']['content_digest'] == results['optimized']['content_digest']
    assert json.dumps(report, sort_keys=True) == original
    return {**results, 'findings': findings, 'cloud_calls': 0, 'identical_artifact_contents': True,
        'input_unchanged': True, 'speedup': round(statistics.median(results['baseline']['seconds']) /
                                                statistics.median(results['optimized']['seconds']), 2),
        'limitations': 'Synthetic complete hosted artifact write stage with zero-latency simulated S3. '
                       'Excludes grouping, native expansion, Markdown generation, evaluation and cloud collection.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--findings', type=int, default=50000)
    args = parser.parse_args()
    print(json.dumps(compare(args.findings), indent=2))
