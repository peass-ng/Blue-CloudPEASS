"""Compare repeated network-page CPU with an earlier projection.py; synthetic, offline."""
import argparse
import importlib.util
import json
from pathlib import Path
import statistics
import time

from peaso.analysis.projection import GraphPageIndex


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--resources', type=int, default=20000)
    args = parser.parse_args()
    if args.resources < 50:
        parser.error('--resources must be at least 50')
    spec = importlib.util.spec_from_file_location('peaso.analysis._paging_baseline', args.baseline)
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    count = args.resources // 50 * 50
    nodes = [{'id': 'vpc', 'type': 'vpc', 'label': 'Application'}]
    for subnet in range(count // 50):
        nodes.append({'id': f's-{subnet}', 'type': 'subnet', 'parent_id': 'vpc', 'label': f'Subnet {subnet}'})
        nodes.extend({'id': f'n-{subnet * 50 + i}', 'type': 'instance', 'parent_id': f's-{subnet}',
                      'label': f'Instance {i}'} for i in range(50))
    graph = {'nodes': nodes, 'edges': [{'id': f'e-{i}', 'source': f'n-{i}',
             'target': f'n-{(i * 37 + 91) % count}', 'type': 'route'} for i in range(count)]}
    samples = []
    for _ in range(3):
        started = time.process_time()
        index = GraphPageIndex(graph, 120)
        prepare = time.process_time() - started
        pages = list(range(0, len(index.pages), max(1, len(index.pages) // 22)))
        started = time.process_time()
        before = [baseline.page_graph(graph, page, 120) for page in pages]
        original = time.process_time() - started
        started = time.process_time()
        after = [index.page(page) for page in pages]
        optimized = time.process_time() - started
        assert before == after
        samples.append({'baseline_cpu': original, 'indexed_cpu_including_preparation': prepare + optimized})
    print(json.dumps({'synthetic_only': True, 'cloud_calls': 0, 'exact_response_parity': True,
                      'nodes': len(nodes), 'edges': len(graph['edges']), 'page_requests': len(pages),
                      'samples': samples,
                      'baseline_cpu_median': statistics.median(s['baseline_cpu'] for s in samples),
                      'indexed_cpu_median': statistics.median(s['indexed_cpu_including_preparation'] for s in samples)}, indent=2))


if __name__ == '__main__':
    main()
