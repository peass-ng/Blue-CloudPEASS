"""Reproducible offline AWS contract inventory and bounded predicate gate.

Run with .venv/bin/python scripts/audit_aws_native_contracts.py --run-gate.
This imports native checks and collector definitions, but never invokes AWS.
Source/fixture presence is structural evidence; only recorded test execution is
runtime evidence. No automated inventory can certify all provider semantics.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import inspect
import json
import lzma
import os
from functools import wraps
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DEFAULT_RECEIPTS = Path('/tmp/peasso-aws-review-20261019/native')
LEDGER = ROOT / 'docs/aws-review/native-contracts.json'
KNOWN_FIELD_GAPS = {'aws_cis_ec2_userdata_embedded_secrets': {
    'field': 'UserDataSecretIndicators',
    'owner': 'coordinator',
    'finding': 'Coordinator confirmed that the active evaluator expected this field but the old EC2 collector produced only UserDataIndicators.',
    'status': 'owner_fix_requires_explicit_collector_contract_recheck'},
    'aws_backup_copy_encrypted': {
        'field': 'CreatedBy.CopyJobId', 'owner': 'coordinator',
        'finding': 'The installed AWS RecoveryPointCreator shape has backup-plan/rule metadata and no CopyJobId; the exact archived copy-inference predicate has no native producer for this field.',
        'status': 'archived_exact_predicate_has_no_native_field_producer'}}

# Each parameterized shared test is restricted to AWS by the plugin below.
# Directed tests exercise native data authority, not evidence-copy formatting.
GATE = [
    'tests/test_peaso_checks.py::test_every_check_has_behavior_fixtures',
    'tests/test_peaso_checks.py::test_unavailable_inventory_never_passes',
    'tests/test_peaso_checks.py::test_partial_inventory_carries_resource_evidence_and_unknown_remainder',
    'tests/test_peaso_checks.py::test_nested_denied_and_malformed_are_unknown',
    'tests/test_aws_native_contract_review.py',
    'tests/test_peaso_checks_aws_a_iam.py',
    'tests/test_peaso_checks_aws_a_iam_policies.py',
    'tests/test_peaso_aws_iam_contract.py',
    'tests/test_peaso_aws_iam_normalization_authority.py',
    'tests/test_peaso_aws_core_ingress_imds_authority.py',
    'tests/test_peaso_checks_claude_aws_a.py',
    'tests/test_peaso_aws_launch_template_imdsv2.py',
    'tests/test_peaso_checks_aws_a_s3.py',
    'tests/test_peaso_s3_account_block_authority.py',
    'tests/test_peaso_aws_bucket_field_authority.py',
    'tests/test_peaso_checks_aws_b_rds_tls_representation.py',
    'tests/test_peaso_checks_aws_b_rds_cluster_tls_evidence.py',
    'tests/test_peaso_checks_aws_b_rds_iam_auth_applicability.py',
    'tests/test_peaso_checks_aws_a_cloudtrail.py',
    'tests/test_peaso_checks_aws_a_cloudtrail_variants.py',
    'tests/test_peaso_aws_cloudtrail_delivery_native.py',
    'tests/test_peaso_compliance_new_aws_guardduty.py',
    'tests/test_peaso_collectors_aws.py',
    'tests/test_peaso_collectors_aws_gap.py',
    'tests/test_peaso_collectors_aws_cb_ca.py',
    'tests/test_peaso_aws_retry_contract.py',
]


def source_ref(function):
    function = inspect.unwrap(function)
    path = Path(inspect.getsourcefile(function)).resolve()
    source, line = inspect.getsourcelines(function)
    return {'file': str(path.relative_to(ROOT)), 'line': line,
            'qualname': function.__qualname__,
            'sha256': hashlib.sha256(''.join(source).encode()).hexdigest()}


def dispatch_contract(check):
    """Identify per-ID generic dispatch targets without guessing by filename."""
    from peaso.checks.facts import FIELD_SPECS
    function = inspect.unwrap(check.evaluate)
    helpers = []
    mapping = function.__globals__.get('EVALUATORS', {})
    if isinstance(mapping, dict) and callable(mapping.get(check.id)):
        helpers.append(source_ref(mapping[check.id]))
    if check.id.startswith('aws_security_group_') and callable(function.__globals__.get('_security_group')):
        helpers.append(source_ref(function.__globals__['_security_group']))
    candidates = list(function.__defaults__ or ())
    for cell in function.__closure__ or ():
        try:
            candidates.append(cell.cell_contents)
        except ValueError:
            pass
    for candidate in candidates:
        if callable(candidate) and getattr(candidate, '__module__', '').startswith('peaso.checks'):
            ref = source_ref(candidate)
            if ref not in helpers:
                helpers.append(ref)
    result = {'helpers': helpers}
    if check.id in FIELD_SPECS:
        spec = FIELD_SPECS[check.id]
        result['field_contract'] = {**spec, 'expected': spec['expected'].__name__}
    return result


def registry():
    from peaso.checks import CHECKS
    return sorted((check for check in CHECKS if check.provider == 'aws'), key=lambda c: c.id)


def active_ids():
    catalog = json.loads((ROOT / 'peaso/rulepacks/native_catalog.json').read_text())
    return {row['id'] for row in catalog['checks'] if row['provider'] == 'aws'}


def behavior_module():
    """Read the bundled missing fixture without materializing shared files."""
    from importlib import import_module
    from unittest.mock import patch
    original = Path.read_text
    bundle = None
    def read(path, *args, **kwargs):
        nonlocal bundle
        try:
            return original(path, *args, **kwargs)
        except FileNotFoundError:
            relative = str(path.resolve().relative_to(ROOT))
            if bundle is None:
                bundle = json.loads(lzma.decompress((ROOT / 'tests/fixtures/release-test-inputs.json.xz').read_bytes()))['files']
            if relative not in bundle:
                raise
            entry = bundle[relative]
            if hashlib.sha256(entry['text'].encode()).hexdigest() != entry['sha256']:
                raise ValueError('bundled fixture digest mismatch: ' + relative)
            return entry['text']
    with patch.object(Path, 'read_text', read):
        return import_module('tests.test_peaso_checks')


def producer_contracts():
    from peaso.collectors import aws
    from peaso.collectors.bulk_evidence import ALIASES, declared_types
    aliases = ALIASES['aws']
    # Exact dispatch branches are stronger than a string occurrence in source.
    tree = ast.parse((ROOT / 'peaso/collectors/aws.py').read_text())
    branches = defaultdict(list)
    emissions = defaultdict(list)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                node.func.id == 'append' and node.args and isinstance(node.args[0], ast.Constant) and
                isinstance(node.args[0].value, str)):
            emissions[node.args[0].value].append({'file': 'peaso/collectors/aws.py', 'line': node.lineno})
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        test = node.test
        if not isinstance(test.left, ast.Name) or test.left.id != 'kind':
            continue
        try:
            value = ast.literal_eval(test.comparators[0])
        except (ValueError, TypeError):
            continue
        values = [value] if isinstance(value, str) else value if isinstance(value, (set, tuple, list)) else []
        for kind in values:
            branches[kind].append({'file': 'peaso/collectors/aws.py', 'line': node.lineno})
    kinds = {dep for check in registry() for dep in check.dependencies}
    result = {}
    for kind in sorted(kinds):
        native = aliases.get(kind, kind)
        row = {'native_type': native, 'alias': native != kind,
               'supported': native in aws.AWS_TYPES,
               'dispatch_branches': branches[native], 'direct_emissions': emissions[native]}
        if native in aws.SPECS:
            row['list_spec'] = list(aws.SPECS[native])
        if native in aws.FETCHERS:
            row['fetcher'] = source_ref(aws.FETCHERS[native])
        if native in aws.ENRICHERS:
            row['enricher'] = source_ref(aws.ENRICHERS[native])
        row['producer_found'] = row['supported'] and bool(row.get('list_spec') or row.get('fetcher') or branches[native] or emissions[native])
        if not row['supported']:
            row['unavailable_projection'] = kind in declared_types('aws')
        result[kind] = row
    return result


def fixture_definitions(check_ids):
    """Literal references only: deliberately never called test coverage."""
    refs = defaultdict(set)
    paths = sorted(set((ROOT / 'peaso/checks').glob('*.json')) |
                   set((ROOT / 'tests/fixtures').glob('*.json')) |
                   set((ROOT / 'tests').glob('test*.py')))
    for path in paths:
        if path.suffix == '.py':
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in check_ids:
                    refs[node.value].add(f'{path.relative_to(ROOT)}:{node.lineno}')
        else:
            # JSON literal check IDs can appear as keys or values.
            text = path.read_text()
            for cid in check_ids:
                if json.dumps(cid) in text:
                    refs[cid].add(str(path.relative_to(ROOT)))
    return refs


def uncertainty_probes(checks):
    CASES = behavior_module().CASES
    results = {}
    for check in checks:
        cases = CASES.get(check.id, {})
        index = deepcopy(cases.get('index', {}))
        row = {}
        for name, data in [('missing', {}), ('denied', {'collection_status': 'denied'}),
                           ('partial', {'collection_status': 'partial'}), ('malformed', None)]:
            try:
                row[name] = check.evaluate(data, deepcopy(index))[0]
            except Exception as exc:
                row[name] = 'EXCEPTION:' + type(exc).__name__
        if check.target == 'scope' and 'pass' in cases:
            partial_index = deepcopy(cases.get('pass_index', cases.get('case_indices', {}).get('pass', index)))
            envelopes = partial_index.get('collections', {})
            changed = 0
            for dep in check.dependencies:
                for envelope in envelopes.get(dep, []):
                    if isinstance(envelope, dict):
                        envelope['status'] = 'partial'
                        changed += 1
            if changed:
                row['all_declared_dependencies_partial'] = check.evaluate(deepcopy(cases['pass']), partial_index)[0]
        results[check.id] = row
    return results


# Optional pytest plugin, used solely by --run-gate. Keep provider facts out of
# receipts: store check IDs, test node IDs and status counters, never input data.
_CURRENT = None
_CALLS = defaultdict(lambda: defaultdict(Counter))
_PARAMETERS = defaultdict(set)
_OUTCOMES = {}
_ORIGINALS = []


def pytest_collection_modifyitems(config, items):
    from peaso.checks import CHECKS
    aws_ids = {c.id for c in CHECKS if c.provider == 'aws'}
    selected, deselected = [], []
    for item in items:
        params = getattr(getattr(item, 'callspec', None), 'params', {})
        check = params.get('check')
        if check is not None and getattr(check, 'provider', None) != 'aws':
            deselected.append(item)
            continue
        selected.append(item)
        for value in params.values():
            cid = getattr(value, 'id', None) if not isinstance(value, str) else value
            if isinstance(cid, str) and cid in aws_ids:
                _PARAMETERS[cid].add(item.nodeid)
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)
    for check in CHECKS:
        if check.provider != 'aws':
            continue
        original = check.evaluate
        @wraps(original)
        def instrumented(item, index, _evaluate=original, _cid=check.id):
            result = _evaluate(item, index)
            if _CURRENT is not None:
                _CALLS[_cid][_CURRENT][result[0]] += 1
            return result
        # Keep the registry's public one-level source-introspection contract.
        # The original safe wrapper still executes inside instrumented().
        instrumented.__wrapped__ = getattr(original, '__wrapped__', original)
        _ORIGINALS.append((check, original))
        object.__setattr__(check, 'evaluate', instrumented)


def pytest_runtest_setup(item):
    global _CURRENT
    _CURRENT = item.nodeid


def pytest_runtest_logreport(report):
    if report.when == 'call' or report.failed:
        _OUTCOMES[report.nodeid] = report.outcome


def pytest_sessionfinish(session, exitstatus):
    for check, original in _ORIGINALS:
        object.__setattr__(check, 'evaluate', original)
    path = os.environ.get('AWS_NATIVE_AUDIT_RECEIPT')
    if path:
        receipt = {'exitstatus': int(exitstatus), 'test_outcomes': _OUTCOMES,
                   'parameterized_check_nodes': {cid: sorted(nodes) for cid, nodes in _PARAMETERS.items()},
                   'predicate_calls': {cid: dict(nodes) for cid, nodes in _CALLS.items()}}
        Path(path).write_text(json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')


def build_ledger(receipt=None, field_receipts=None):
    from peaso.checks.native_only import exclusions
    module = behavior_module()
    CASES, STALE_PASS_CASES, STALE_FAIL_CASES = module.CASES, module.STALE_PASS_CASES, module.STALE_FAIL_CASES
    checks = registry()
    field_receipts = field_receipts or {}
    catalog_path = ROOT / 'peaso/rulepacks/native_catalog.json'
    catalog_digest = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    active = active_ids()
    archived = exclusions()
    producers = producer_contracts()
    refs = fixture_definitions({c.id for c in checks})
    probes = uncertainty_probes(checks)
    receipt = receipt or {}
    calls = receipt.get('predicate_calls', {})
    outcomes = receipt.get('test_outcomes', {})
    rows = []
    for check in checks:
        fixtures = CASES.get(check.id, {})
        executed = calls.get(check.id, {})
        passed = {node: statuses for node, statuses in executed.items() if outcomes.get(node) == 'passed'}
        observed = Counter()
        for statuses in passed.values():
            observed.update(statuses)
        expected = {name: name.upper() for name in ('pass', 'fail', 'unknown', 'manual') if name in fixtures}
        inventory_tests = {}
        for node in receipt.get('parameterized_check_nodes', {}).get(check.id, []):
            if node.startswith('tests/test_peaso_checks.py::test_unavailable_inventory_never_passes['):
                state, expected_status, _cid = node.split('[', 1)[1].rstrip(']').split('-', 2)
                inventory_tests[state] = {'test_outcome': outcomes.get(node, 'collected_not_executed'),
                    'expected': 'rule_specific_complete_absence' if state == 'empty' and check.target == 'scope' else expected_status}
        if check.id in STALE_PASS_CASES and 'pass' in expected:
            expected['pass'] = 'UNKNOWN'
        if check.id in STALE_FAIL_CASES and 'fail' in expected:
            expected['fail'] = 'UNKNOWN'
        if fixtures.get('fail_expect') is not None and 'fail' in expected:
            expected['fail'] = fixtures['fail_expect']
        rows.append({'id': check.id, 'active': check.id in active, 'kind': check.kind,
                     'admission_reason': 'active_native_catalog' if check.id in active else
                         archived.get(check.id, {}).get('reason', 'absent_from_active_native_catalog'),
                     'target': check.target, 'dependencies': check.dependencies,
                     'evaluate': source_ref(check.evaluate),
                     'dispatch': dispatch_contract(check),
                     'fixture_case_expectations': expected,
                     'literal_source_references_not_coverage': sorted(refs[check.id]),
                     'parameterized_test_nodes': receipt.get('parameterized_check_nodes', {}).get(check.id, []),
                     'runtime_inventory_checks': inventory_tests,
                     'passing_predicate_test_nodes': sorted(passed),
                     'observed_status_counts': dict(sorted(observed.items())),
                     'uncertainty_probes': probes[check.id],
                     'known_field_contract_findings': ([{**KNOWN_FIELD_GAPS[check.id],
                         **({'status': 'collector_contract_rechecked', 'receipt': field_receipts[check.id]}
                            if check.id in field_receipts else {})}] if check.id in KNOWN_FIELD_GAPS else []),
                     'review': {'structural': True, 'semantic': 'directed_runtime_cases' if any(
                         not node.startswith(('tests/test_peaso_checks.py::', 'tests/test_aws_native_contract_review.py::'))
                         for node in passed) else 'shared_runtime_cases' if passed else 'not_executed',
                         'runtime_mocked': bool(passed), 'live': False,
                         'collector_shape': 'producer_definition_resolved' if all(producers[d]['producer_found'] for d in check.dependencies) else 'unavailable_projection',
                         'complete_semantic_review': False}})
    blockers = []
    for cid in sorted(active - {check.id for check in checks}):
        blockers.append({'id': cid, 'reason': 'active_catalog_check_missing_from_runtime_registry'})
    if hashlib.sha256(catalog_path.read_bytes()).hexdigest() != catalog_digest:
        blockers.append({'id': None, 'reason': 'catalog_changed_during_audit_capture'})
    for row in rows:
        if not row['active']:
            continue
        if not row['passing_predicate_test_nodes']:
            blockers.append({'id': row['id'], 'reason': 'no_passing_predicate_execution_receipt'})
        for finding in row['known_field_contract_findings']:
            if finding['status'] != 'collector_contract_rechecked':
                blockers.append({'id': row['id'], 'reason': 'collector_field_contract_requires_owner_recheck', 'field': finding['field']})
        for dep in row['dependencies']:
            if not producers[dep]['producer_found']:
                blockers.append({'id': row['id'], 'reason': 'unresolved_collector_producer', 'dependency': dep})
        for probe, status in row['uncertainty_probes'].items():
            if status == 'PASS' or status.startswith('EXCEPTION:'):
                blockers.append({'id': row['id'], 'reason': 'uncertainty_probe_requires_review', 'probe': probe, 'status': status})
    return {'schema_version': 1, 'scope': 'all registered AWS checks; active catalog admission explicit',
            'native_catalog_sha256': catalog_digest,
            'limitations': ['Mocked fixtures do not establish live AWS API compatibility.',
                           'Literal test references are not executed test coverage.',
                           'Shared truth cases are not exhaustive semantic verification.',
                           'Partial resource inventories may retain an observed resource PASS plus UNKNOWN remainder.',
                           'Collector definition presence does not prove every required nested field is collected.',
                           'No per-check complete semantic review is claimed.'],
            'counts': {'registered': len(rows), 'active': sum(r['active'] for r in rows), 'catalog_active': len(active),
                       'archived': sum(not r['active'] for r in rows),
                       'runtime_mocked': sum(r['review']['runtime_mocked'] for r in rows),
                       'directed_runtime_cases': sum(r['review']['semantic'] == 'directed_runtime_cases' for r in rows)},
            'gate': {'initial_exitstatus': receipt.get('exitstatus'),
                     'exitstatus': (int(any(value == 'failed' for value in outcomes.values()))
                                    if outcomes and receipt.get('exitstatus') in (0, 1) else receipt.get('exitstatus')),
                     'tests': dict(Counter(outcomes.values())),
                     'command': [sys.executable, '-m', 'pytest', '-p', 'scripts.audit_aws_native_contracts', *GATE]},
            'semantic_gaps': {'active_without_observed_pass': [r['id'] for r in rows if r['active'] and not r['observed_status_counts'].get('PASS')],
                              'active_without_observed_fail': [r['id'] for r in rows if r['active'] and not r['observed_status_counts'].get('FAIL')],
                              'meaning': 'Missing status witnesses are review gaps, not proof of a defect; some controls intentionally use MANUAL or UNKNOWN instead of FAIL.'},
            'producers': producers, 'blockers': blockers, 'checks': rows}


def merge_receipts(primary, supplements):
    receipt = deepcopy(primary or {})
    for extra in supplements:
        receipt.setdefault('test_outcomes', {}).update(extra.get('test_outcomes', {}))
        for cid, nodes in extra.get('parameterized_check_nodes', {}).items():
            receipt.setdefault('parameterized_check_nodes', {}).setdefault(cid, [])
            receipt['parameterized_check_nodes'][cid] = sorted(set(receipt['parameterized_check_nodes'][cid]) | set(nodes))
        for cid, nodes in extra.get('predicate_calls', {}).items():
            receipt.setdefault('predicate_calls', {}).setdefault(cid, {}).update(nodes)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-gate', action='store_true')
    parser.add_argument('--receipts', type=Path, default=DEFAULT_RECEIPTS)
    parser.add_argument('--output', type=Path, default=LEDGER)
    parser.add_argument('--supplement', type=Path, action='append', default=[],
                        help='Additional bounded predicate execution receipt; repeat as needed')
    parser.add_argument('--junit-recheck', type=Path, action='append', default=[],
                        help='Apply an explicit corrected-test JUnit receipt, retaining original gate history')
    parser.add_argument('--field-contract-receipt', action='append', default=[], metavar='CHECK_ID=JUNIT_PATH',
                        help='Explicit owner-supplied collector contract verification for a known field gap')
    args = parser.parse_args(argv)
    args.receipts.mkdir(parents=True, exist_ok=True)
    receipt_path = args.receipts / 'predicate-execution.json'
    gate_exit = 0
    if args.run_gate:
        env = {**os.environ, 'AWS_NATIVE_AUDIT_RECEIPT': str(receipt_path)}
        command = [sys.executable, '-m', 'pytest', '-p', 'scripts.audit_aws_native_contracts',
                   '-q', '--tb=short', '-o', 'addopts=',
                   '--junitxml=' + str(args.receipts / 'pytest.xml'), *GATE]
        gate_exit = subprocess.run(command, cwd=ROOT, env=env).returncode
    paths = ([receipt_path] if receipt_path.exists() else []) + args.supplement
    receipts = [json.loads(path.read_text()) for path in paths]
    receipt = merge_receipts(receipts[0] if receipts else None, receipts[1:])
    for path in args.junit_recheck:
        for case in ET.parse(path).iter('testcase'):
            node = case.attrib['classname'].replace('.', '/') + '.py::' + case.attrib['name']
            outcome = ('failed' if case.find('failure') is not None or case.find('error') is not None else
                       'skipped' if case.find('skipped') is not None else 'passed')
            receipt.setdefault('test_outcomes', {})[node] = outcome
    field_receipts = {}
    for entry in args.field_contract_receipt:
        cid, path_value = entry.split('=', 1)
        if cid not in KNOWN_FIELD_GAPS:
            parser.error('field receipt must identify a known field gap: ' + cid)
        path = Path(path_value)
        suites = list(ET.parse(path).iter('testsuite'))
        if not suites or any(int(s.attrib.get('errors', 0)) or int(s.attrib.get('failures', 0)) for s in suites):
            parser.error('collector field receipt contains errors or failures: ' + str(path))
        if not any(int(s.attrib.get('tests', 0)) > int(s.attrib.get('skipped', 0)) for s in suites):
            parser.error('collector field receipt has no executed tests: ' + str(path))
        field_receipts[cid] = {'file': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                               'asserted_by': 'explicit owner-provided check-ID/collector-test association'}
    ledger = build_ledger(receipt, field_receipts)
    ledger['gate']['receipts'] = [{'file': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                 'exitstatus': data.get('exitstatus'),
                                 'tests': dict(Counter(data.get('test_outcomes', {}).values()))}
                                for path, data in zip(paths, receipts)]
    ledger['gate']['junit_rechecks'] = [{'file': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                                      for path in args.junit_recheck]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(ledger, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'counts': ledger['counts'], 'gate': ledger['gate']['tests'],
                      'blockers': ledger['blockers'], 'output': str(args.output)}, indent=2))
    return gate_exit or ledger['gate']['exitstatus'] or (1 if ledger['blockers'] else 0)


if __name__ == '__main__':
    raise SystemExit(main())
