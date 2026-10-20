"""Record every registered GCP predicate and its executed, bounded test evidence.

Use --run-gate once for a baseline, then --supplement for directed rechecks.
The pytest plugin records IDs and outcomes, never cloud documents or secrets.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import wraps
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
REVIEW = ROOT / 'docs/gcp-review'
DEFAULT_RECEIPTS = Path('/tmp/peasso-gcp-review-20261019/native')
_CURRENT = None
_CALLS = defaultdict(lambda: defaultdict(Counter))
_OUTCOMES = {}
_ORIGINALS = []


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pytest_collection_modifyitems(config, items):
    from peaso.checks import CHECKS
    selected, deselected = [], []
    for item in items:
        check = getattr(getattr(item, 'callspec', None), 'params', {}).get('check')
        (deselected if check is not None and getattr(check, 'provider', None) != 'gcp'
         else selected).append(item)
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)
    for check in CHECKS:
        if check.provider != 'gcp':
            continue
        original = check.evaluate

        @wraps(original)
        def recorded(item, index, _evaluate=original, _cid=check.id):
            result = _evaluate(item, index)
            if _CURRENT is not None:
                _CALLS[_cid][_CURRENT][result[0]] += 1
            return result

        recorded.__wrapped__ = getattr(original, '__wrapped__', original)
        _ORIGINALS.append((check, original))
        object.__setattr__(check, 'evaluate', recorded)


def pytest_runtest_setup(item):
    global _CURRENT
    _CURRENT = item.nodeid


def pytest_runtest_logreport(report):
    if report.when == 'call' or report.failed:
        _OUTCOMES[report.nodeid] = report.outcome


def pytest_sessionfinish(session, exitstatus):
    for check, original in _ORIGINALS:
        object.__setattr__(check, 'evaluate', original)
    target = os.environ.get('GCP_NATIVE_AUDIT_RECEIPT')
    if target:
        Path(target).write_text(json.dumps({
            'exitstatus': int(exitstatus), 'test_outcomes': _OUTCOMES,
            'predicate_calls': {cid: dict(nodes) for cid, nodes in _CALLS.items()},
        }, sort_keys=True) + '\n')


def gate():
    from tests.compliance_draft_isolation import DRAFT_TEST_MODULES, STAGED_UNSELECTED_TEST_MODULES
    shared = ['tests/test_peaso_checks.py::' + name for name in (
        'test_every_check_has_behavior_fixtures', 'test_unavailable_inventory_never_passes',
        'test_partial_inventory_carries_resource_evidence_and_unknown_remainder',
        'test_nested_denied_and_malformed_are_unknown')]
    files = [str(p.relative_to(ROOT)) for p in sorted((ROOT / 'tests').glob('test_*gcp*.py'))
             if not any(word in p.name for word in ('attack_detection', 'privesc', 'aws', 'k8s'))
             and p.name not in DRAFT_TEST_MODULES and p.name not in STAGED_UNSELECTED_TEST_MODULES]
    return shared + files


def inventory(receipts=()):
    from peaso.checks import CHECKS
    from peaso.checks.native_only import exclusions
    catalog_path = ROOT / 'peaso/rulepacks/native_catalog.json'
    catalog = {r['id']: r for r in json.loads(catalog_path.read_text())['checks'] if r['provider'] == 'gcp'}
    archived = exclusions()
    sources = [r for r in json.loads((ROOT / 'peaso/rulepacks/upstream_manifest.json').read_text())['checks']
               if r['provider'] == 'gcp']
    source_ids = defaultdict(list)
    for source in sources:
        for cid in source.get('native_checks', []):
            source_ids[cid].append(source['check_id'])
    outcomes, calls, lineage = {}, defaultdict(dict), []
    for path in receipts:
        data = json.loads(path.read_text())
        outcomes.update(data['test_outcomes'])
        for cid, nodes in data['predicate_calls'].items():
            calls[cid].update(nodes)
        lineage.append({'file': str(path), 'sha256': digest(path), 'initial_exitstatus': data['exitstatus']})
    rows = []
    for check in CHECKS:
        if check.provider != 'gcp':
            continue
        fn = inspect.unwrap(check.evaluate)
        file = Path(inspect.getsourcefile(fn))
        passing = {node: statuses for node, statuses in calls[check.id].items() if outcomes.get(node) == 'passed'}
        statuses = Counter()
        for counts in passing.values():
            statuses.update(counts)
        native = catalog.get(check.id, {})
        rows.append({'id': check.id, 'active': check.id in catalog, 'title': check.title,
                     'kind': check.kind, 'target': check.target, 'dependencies': list(check.dependencies),
                     'source': str(file.relative_to(ROOT)), 'source_sha256': digest(file),
                     'callback_sha256': hashlib.sha256(inspect.getsource(fn).encode()).hexdigest(),
                     'archive_reason': archived.get(check.id, {}).get('reason') if check.id not in catalog else None,
                     'ui_group': native.get('finding_type'), 'framework_ids': native.get('framework_ids', []),
                     'source_ids': sorted(source_ids[check.id]),
                     'passing_test_nodes': sorted(passing), 'observed_status_counts': dict(statuses),
                     'code_review': 'pending', 'producer_review': 'pending',
                     'upstream_semantic_equivalence': 'not_certified', 'live_verified': False})
    return {'captured_at_utc': datetime.now(timezone.utc).isoformat(),
            'scope': 'Every registered GCP check; archived definitions explicitly distinguished.',
            'counts': {'registered': len(rows), 'active': len(catalog), 'archived': sum(not r['active'] for r in rows),
                       'callbacks_executed_in_passing_tests': sum(bool(r['passing_test_nodes']) for r in rows)},
            'test_outcomes': dict(Counter(outcomes.values())), 'receipts': lineage,
            'catalog_sha256': digest(catalog_path), 'checks': sorted(rows, key=lambda r: r['id']),
            'limits': ['Invocation and fixtures do not certify semantics or live field production.',
                       'Code and producer reviews remain pending until individually recorded.',
                       'Upstream lineage does not establish equivalent predicates.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-gate', action='store_true')
    parser.add_argument('--receipts', type=Path, default=DEFAULT_RECEIPTS)
    parser.add_argument('--supplement', type=Path, action='append', default=[])
    args = parser.parse_args()
    args.receipts.mkdir(parents=True, exist_ok=True)
    receipt = args.receipts / 'execution.json'
    exitcode = 0
    if args.run_gate:
        command = [sys.executable, '-m', 'pytest', '-q', '-p', 'scripts.audit_gcp_native_contracts',
                   '-o', 'addopts=', '--tb=short', '--junitxml=' + str(args.receipts / 'pytest.xml'), *gate()]
        (args.receipts / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
        exitcode = subprocess.run(command, cwd=ROOT, env={**os.environ, 'GCP_NATIVE_AUDIT_RECEIPT': str(receipt)}).returncode
    report = inventory(([receipt] if receipt.exists() else []) + args.supplement)
    REVIEW.mkdir(parents=True, exist_ok=True)
    (REVIEW / 'native-contracts.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'counts': report['counts'], 'test_outcomes': report['test_outcomes']}))
    return exitcode


if __name__ == '__main__':
    raise SystemExit(main())
