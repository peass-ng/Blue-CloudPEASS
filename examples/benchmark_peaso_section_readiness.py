"""Exact section differential and complete checkpoint-readiness poll replay.

The plan contains collection keys and selected-check metadata, never
native resource contents. Real planning output must retain its set semantics
when restored from JSON. No evaluator, artifact write or cloud call is used.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import sys
import threading
import time
from types import SimpleNamespace


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def differential(before, after, cases):
    rng = random.Random(431172)
    digest = hashlib.sha256()
    for _ in range(cases):
        provider = rng.choice(('aws', 'gcp', 'azure', 'k8s'))
        kinds = [f'kind{i}' for i in range(8)]
        scopes = rng.choices(['a/r1', 'a/r2', 'b/r1', '*', '/', ''], k=rng.randrange(7))
        needed = {f'section{i}': set(rng.sample(kinds, rng.randrange(9)))
                  for i in range(rng.randrange(8))}
        rows = {(rng.choice(kinds), rng.choice(['a/r1', 'a/r2', 'b/r1', 'a/global', 'other'])):
                {'status': rng.choice(('collected', 'empty', 'partial', 'denied', 'unknown'))}
                for _ in range(rng.randrange(50))}
        revisions = {key: rng.randrange(-10, 100) for key in rows if rng.randrange(3)}
        options = dict(finished=bool(rng.randrange(2)), global_types=set(rng.sample(kinds, 3)),
                       global_scope=rng.choice((None, 'global', 'tenant')))
        inputs = (provider, scopes, needed, rows, revisions)
        preserved = copy.deepcopy((inputs, options))
        expected = before.states(*inputs, **options)
        actual = after.states(*inputs, **options)
        assert actual == expected
        assert (inputs, options) == preserved
        digest.update(json.dumps(actual, sort_keys=True, separators=(',', ':')).encode())
    return dict(cases=cases, exact_parity=True, no_input_mutation=True,
                outputs_sha256=digest.hexdigest())


def prepare_plan(snapshot, selectors):
    from peaso.incremental import CheckpointSession
    if 'data' in selectors:
        selectors = selectors['data']
        selectors = json.loads(selectors) if isinstance(selectors, str) else selectors
    class ManualSession(CheckpointSession):
        def _background(self):
            pass
    request = {key: selectors[key] for key in ('checks', 'categories', 'frameworks') if key in selectors}
    request['connector'] = {'provider': snapshot['provider'], 'scopes': snapshot['scopes']}
    session = ManualSession(request, lambda *_: None, lambda value: value)
    session.thread.join()
    return dict(provider=session.provider, scopes=session.effective_scopes,
        needed={key: sorted(value) for key, value in session.section_dependencies.items()},
        global_types=sorted(session.global_types), global_scope=session.global_scope,
        native=[dict(id=row.id, kind=row.kind, category=row.category,
                     dependencies=list(row.dependencies)) for row in session.native_checks],
        analyzed=session.analysis_checks, privesc_selected=session.privesc is not None,
        graph_categories=sorted(session.graph_categories),
        collections=[[row['type'], row['scope'], row['status'], i]
                     for i, row in enumerate(snapshot['collections'], 1)])


def replay(incremental, sections, plan, iterations):
    # Match the production JSON->set restoration shape for both implementations.
    sys.modules['peaso.scan_sections'] = sections
    session = incremental.CheckpointSession.__new__(incremental.CheckpointSession)
    session.provider = plan['provider']
    session.effective_scopes = plan['scopes']
    session.section_dependencies = {key: set(value) for key, value in plan['needed'].items()}
    session.global_types, session.global_scope = set(plan['global_types']), plan['global_scope']
    session.native_checks = [SimpleNamespace(**row) for row in plan['native']]
    session.analysis_checks = plan['analyzed']
    session.privesc = {} if plan['privesc_selected'] else None
    session.graph_categories = set(plan['graph_categories'])
    session.collections = {(kind, scope): {'status': status}
        for kind, scope, status, revision in plan['collections']}
    session.collection_revisions = {(kind, scope): revision
        for kind, scope, status, revision in plan['collections']}
    session.collection_finished = False
    session.sequence, session.last_published = 2, 1
    session.publish_lock, session.lock = threading.Lock(), threading.RLock()
    session.published_categories = {row.category for row in session.native_checks}
    session.published_categories.update(row['category'] for row in session.analysis_checks)
    session.published_categories.add('privesc')
    session.published_sections = set(session.section_dependencies)
    session.clock = time.monotonic
    session.last_time = session.clock()
    session.min_report_interval = 1e9
    session.collection_stride, session.interval = 24, 8
    start, cpu = time.perf_counter(), time.process_time()
    for _ in range(iterations):
        assert session._maybe_publish() is None
    elapsed, used = time.perf_counter()-start, time.process_time()-cpu
    states = sections.states(session.provider, session.effective_scopes,
        session.section_dependencies, session.collections, session.collection_revisions,
        global_types=session.global_types, global_scope=session.global_scope)
    ready, complete = session._ready(sections=states)
    output = dict(sections=states, ready=ready,
                  complete={key: sorted(value) for key, value in complete.items()})
    return dict(iterations=iterations, wall_seconds=elapsed, cpu_seconds=used,
        collections=len(session.collections), selected_checks=len(session.native_checks),
        output_sha256=hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--baseline-incremental', type=Path, required=True)
    parser.add_argument('--candidate-incremental', type=Path, required=True)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--selectors', type=Path)
    parser.add_argument('--iterations', type=int, default=200)
    parser.add_argument('--cases', type=int, default=5000)
    args = parser.parse_args()
    if args.plan and (args.snapshot or args.selectors):
        parser.error('Use either --plan or both --snapshot and --selectors')
    if not args.plan and not (args.snapshot and args.selectors):
        parser.error('Supply --plan or both --snapshot and --selectors')
    before = module(args.baseline, 'peaso._section_before')
    after = module(args.candidate, 'peaso._section_after')
    diff = differential(before, after, args.cases)
    old_incremental = module(args.baseline_incremental, 'peaso._incremental_before')
    new_incremental = module(args.candidate_incremental, 'peaso._incremental_after')
    plan = (json.loads(args.plan.read_text()) if args.plan else
            prepare_plan(json.loads(args.snapshot.read_text()), json.loads(args.selectors.read_text())))
    old = replay(old_incremental, before, plan, args.iterations)
    new = replay(new_incremental, after, plan, args.iterations)
    assert old['output_sha256'] == new['output_sha256']
    print(json.dumps(dict(cloud_calls=0, differential=diff, before=old, after=new), indent=2))
