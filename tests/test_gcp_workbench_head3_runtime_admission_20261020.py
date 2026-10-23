"""Focused real registry/normal-engine Workbench admission and fault proof."""
from copy import deepcopy
from tests.shared_admission_epoch_compatibility_20261020 import workbench_file_at_epoch
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

import peaso.checks as registry
from peaso.checks import fixtures
from peaso.checks import gcp_workbench_head3_admission_20261020 as admission
from peaso.checks import gcp_workbench_head3_proposal_20261020 as candidate
from peaso.collectors import gcp
from peaso.collectors import gcp_workbench_head3_projection_20261020 as projection
from peaso.engine import evaluate_snapshot, plan_collection

IDS = admission.CHECK_IDS
SCOPE = 'projects/review'
NAME = SCOPE + '/locations/us-central1-a/instances/notebook'
KEYS = dict(zip(IDS, ('notebook-disable-terminal', 'notebook-disable-downloads', projection.KEY)))


@pytest.fixture(scope='module', autouse=True)
def actual_transactional_bundle():
    # The same real transactional installer is exercised before the shared
    # init hook lands; a separate fresh-process node proves that actual hook.
    admission.install_bundle()


class NativeHTTP:
    def __init__(self, rows, *, denied=False, unreachable=False):
        self.rows, self.denied, self.unreachable = rows, denied, unreachable
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        policy = re.fullmatch(r'https://notebooks.googleapis.com/v2/(projects/[^/]+)/locations/[^/]+/instances/[^/]+:getIamPolicy', url)
        if policy:
            assert method == 'GET' and policy[1] in self.rows
            return {'bindings': [], 'version': 3}, 'wb-policy-' + policy[1].split('/')[1]
        match = re.fullmatch(r'https://notebooks.googleapis.com/v2/(projects/[^/]+)/locations/-/instances', url)
        assert method == 'GET' and match and match[1] in self.rows
        if self.denied:
            error = gcp.ReadError('denied', 'api_error', http_status=403)
            error.request_id = 'wb-' + match[1].split('/')[1]
            raise error
        result = {'instances': deepcopy(self.rows[match[1]])}
        if self.unreachable:
            result['unreachable'] = [match[1] + '/locations/us-west1-a']
        return result, 'wb-' + match[1].split('/')[1]


def row(name=NAME, *, state='ACTIVE', metadata=None):
    if metadata is None:
        metadata = {KEYS[IDS[0]]: 'true', KEYS[IDS[1]]: 'true', KEYS[IDS[2]]: '00 19 * * MON'}
    return {'name': name, 'state': state, 'gceSetup': {'metadata': metadata}}


def collect(rows, **transport_options):
    transport = NativeHTTP(rows, **transport_options)
    connector = {'provider': 'gcp', 'scopes': list(rows), 'options': {
        'inventories': ['workbench_instance'], 'include_inherited': False,
        'metrics_scopes': False, 'concurrency': 1}}
    snapshot = gcp.GCPCollector(connector, requirements=['workbench_instance'], transport=transport).collect()
    assert sum(url.endswith('/instances') for _, url in transport.calls) == len(rows)
    return snapshot, transport


def findings(snapshot, ids=IDS):
    result = evaluate_snapshot(snapshot, checks=list(ids))
    assert {finding['check_id'] for finding in result['findings']} == set(ids)
    return result['findings']


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('case,expected', [
    ('pass', 'PASS'), ('fail', 'FAIL'), ('redacted', 'UNKNOWN'),
    ('malformed', 'UNKNOWN'), ('unsupported', 'UNKNOWN'), ('omitted', 'FAIL'),
    ('deleted', 'NOT_APPLICABLE'), ('cross_project', 'UNKNOWN'),
    ('unrecognized_state', 'UNKNOWN'), ('denied_leaf', 'UNKNOWN'),
])
def test_normal_engine_native_row(cid, case, expected):
    native = row()
    key = KEYS[cid]
    if case == 'fail':
        native['gceSetup']['metadata'][key] = '' if key == projection.KEY else 'false'
    elif case == 'redacted':
        native['gceSetup']['metadata'][key] = None
    elif case == 'malformed':
        native['gceSetup']['metadata'][key] = True
    elif case == 'unsupported':
        native['gceSetup']['metadata'][key] = 'unsupported-expression'
    elif case == 'omitted':
        native['gceSetup']['metadata'].pop(key)
    elif case == 'deleted':
        native['state'] = 'DELETED'
    elif case == 'cross_project':
        native['name'] = NAME.replace('/review/', '/other/')
    elif case == 'unrecognized_state':
        native['state'] = 'FUTURE_STATE'
    elif case == 'denied_leaf':
        native['gceSetup']['metadata']['_coverage'] = {key: {'status': 'denied'}}
    snapshot, transport = collect({SCOPE: [native]})
    output = findings(snapshot, [cid])
    assert {finding['status'] for finding in output} == {expected}, output
    assert sum(url.endswith('/instances') for _, url in transport.calls) == 1
    assert 'unsupported-expression' not in json.dumps([f['evidence'] for f in output])


@pytest.mark.parametrize('option', ['denied', 'unreachable'])
def test_unavailable_native_reads_never_become_clean_findings(option):
    snapshot, _ = collect({SCOPE: [row()]}, **{option: True})
    output = findings(snapshot)
    # Normal engine retains its existing explicit DENIED inventory status.
    assert {finding['status'] for finding in output} <= {'UNKNOWN', 'DENIED'}


def test_multi_asset_multi_project_and_saved_json_replay_use_only_existing_list(tmp_path):
    rows = {}
    for scope in ('projects/alpha1', 'projects/bravo1'):
        good = row(scope + '/locations/us-central1-a/instances/good')
        bad = row(scope + '/locations/us-central1-a/instances/bad', metadata={
            KEYS[IDS[0]]: 'false', KEYS[IDS[1]]: 'false', KEYS[IDS[2]]: ''})
        rows[scope] = [good, bad]
    snapshot, transport = collect(rows)
    original = findings(snapshot)
    assert len(original) == 12
    assert sum(f['status'] == 'PASS' for f in original) == 6
    assert sum(f['status'] == 'FAIL' for f in original) == 6
    path = tmp_path / 'saved-native.json'
    path.write_text(json.dumps(snapshot))
    replay = findings(json.loads(path.read_text()))
    assert replay == original
    assert sum(url.endswith('/instances') for _, url in transport.calls) == 2


def test_actual_registered_predicates_cases_and_default_metadata_plan():
    registered = {check.id: check for check in registry.CHECKS}
    for declaration in admission.DECLARATIONS:
        cid = declaration['id']
        check = registered[cid]
        assert inspect.unwrap(check.evaluate) is admission.EVALUATORS[cid]
        assert (check.provider, check.kind, check.category, check.control) == (
            'gcp', 'workbench_instance', 'hardening', 'security_configuration')
        assert check.severity == declaration['severity']
        assert check.dependencies == ['workbench_instance'] and not check.allow_incomplete_failure
        assert fixtures.CASES[cid]['pass'] != fixtures.CASES[cid]['fail']
    planned = plan_collection({'connector': {'provider': 'gcp', 'scopes': [SCOPE], 'options': {}},
                               'checks': list(IDS)})
    assert planned == ['workbench_instance'] or set(planned) == {'workbench_instance'}


def test_idempotent_actual_install_preserves_all_predecessor_objects():
    before, cases, aliases = tuple(registry.CHECKS), dict(fixtures.CASES), dict(registry.CHECK_ALIASES)
    admission.install_bundle()
    assert len(before) == len(registry.CHECKS)
    assert all(left is right for left, right in zip(before, registry.CHECKS))
    assert fixtures.CASES.keys() == cases.keys()
    assert all(fixtures.CASES[cid] is value for cid, value in cases.items())
    assert registry.CHECK_ALIASES == aliases


@pytest.mark.parametrize('mode', ['registry_append', 'cases_write'])
def test_real_transaction_rolls_back_after_partial_registry_or_cases_failure(monkeypatch, mode):
    """Faults act on copied mutable registries using the actual register code."""
    baseline = [check for check in registry.CHECKS if check.id not in IDS]
    base_cases = {cid: value for cid, value in fixtures.CASES.items() if cid not in IDS}

    class FailingChecks(list):
        def append(self, value):
            super().append(value)
            if value.id == IDS[1] and mode == 'registry_append':
                raise OSError('injected registry append failure')

    class FailingCases(dict):
        def __setitem__(self, key, value):
            super().__setitem__(key, value)
            if key == IDS[1] and mode == 'cases_write':
                raise OSError('injected CASES write failure')

    copied_checks, copied_cases = FailingChecks(baseline), FailingCases(base_cases)
    monkeypatch.setattr(registry, 'CHECKS', copied_checks)
    monkeypatch.setattr(fixtures, 'CASES', copied_cases)
    with pytest.raises(OSError):
        admission.install_bundle()
    assert len(copied_checks) == len(baseline)
    assert all(left is right for left, right in zip(copied_checks, baseline))
    assert copied_cases.keys() == base_cases.keys()
    assert all(copied_cases[cid] is value for cid, value in base_cases.items())


@pytest.mark.parametrize('change', ['predicate_attribute', 'predicate_code', 'predicate_defaults',
                                    'grammar', 'import', 'collector_method', 'evaluator_map'])
def test_actual_engine_source_substitution_is_unknown_and_restored_is_pass(monkeypatch, change):
    snapshot, _ = collect({SCOPE: [row()]})
    assert {f['status'] for f in findings(snapshot)} == {'PASS'}
    with monkeypatch.context() as patch:
        if change == 'predicate_attribute':
            patch.setattr(candidate, '_evaluate', lambda *args: ('PASS', {'observed': 'substituted'}))
        elif change == 'predicate_code':
            patch.setattr(candidate._evaluate, '__code__', (lambda *args: ('PASS', {})).__code__)
        elif change == 'predicate_defaults':
            patch.setattr(candidate.terminal_access_disabled, '__defaults__', (None,))
        elif change == 'grammar':
            patch.setattr(projection, 'MAX_SCHEDULE_BYTES', 999)
        elif change == 'import':
            patch.setattr(candidate, 'get', lambda *args: 'true')
        elif change == 'collector_method':
            patch.setattr(gcp.GCPCollector, 'scope_jobs', lambda *args: [])
        else:
            patch.setitem(candidate.EVALUATORS, IDS[0], lambda *args: ('PASS', {}))
        with pytest.raises((RuntimeError, KeyError, TypeError, ValueError, AttributeError)):
            admission.reviewed_inputs()
        assert {f['status'] for f in findings(snapshot)} == {'UNKNOWN'}
    assert {f['status'] for f in findings(snapshot)} == {'PASS'}


def test_disk_source_negative_current_baseline_and_restored(monkeypatch):
    admission.reviewed_inputs()
    path = Path(__file__).resolve().parents[1] / 'peaso/checks/gcp_workbench_head3_proposal_20261020.py'
    original = Path.read_bytes

    def substituted(candidate):
        raw = original(candidate)
        return raw + b'\n# substituted source witness\n' if candidate.resolve() == path else raw

    with monkeypatch.context() as patch:
        patch.setattr(Path, 'read_bytes', substituted)
        with pytest.raises((RuntimeError, ValueError), match='(reviewed source changed|current source mismatch)'):
            admission.reviewed_inputs()
    admission.reviewed_inputs()


def test_preserved_accepted_proposal_bytes_and_exact_legacy_registry_predicates():
    archived = json.loads(gzip.decompress(Path(
        'peaso/checks/gcp_workbench_head3_admission_predecessor_20261020.json.gz').read_bytes()))
    for path, digest in archived['accepted_proposal_files_sha256'].items():
        assert hashlib.sha256(workbench_file_at_epoch(path, digest)).hexdigest() == digest
    current = {check.id: check for check in registry.CHECKS}
    from tests.shared_admission_epoch_compatibility_20261020 import active_shared
    from peaso.checks import aws_workload_command_observed_20261020 as workload
    from peaso.checks import gcp_cloudrun_job_image_secret_review_20261020 as job_image
    active_shared().reviewed_delta()
    job_image.install()
    later = {workload.CHECK, job_image.CHECK_ID}
    assert current.keys() - {check['id'] for check in archived['checks']} == set(IDS) | later
    for prior in archived['checks']:
        check = current[prior['id']]
        function = inspect.unwrap(check.evaluate)
        assert function.__module__ + '.' + function.__qualname__ == prior['qualname']
        assert hashlib.sha256(inspect.getsource(function).encode()).hexdigest() == prior['body_sha256']
        assert check.severity == prior['severity'] and check.kind == prior['kind']


def test_fresh_process_normal_package_import_installs_once():
    code = '''
import inspect
from peaso.checks import CHECKS
from peaso.checks import gcp_workbench_head3_admission_20261020 as admitted
assert sum(c.id in admitted.CHECK_IDS for c in CHECKS) == 3
assert all(inspect.unwrap(next(c for c in CHECKS if c.id == cid).evaluate) is admitted.EVALUATORS[cid] for cid in admitted.CHECK_IDS)
admitted.install_bundle()
assert sum(c.id in admitted.CHECK_IDS for c in CHECKS) == 3
print('normal import exact3 idempotent')
'''
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr
    assert 'normal import exact3 idempotent' in result.stdout


@pytest.mark.parametrize('status', ['PASS', 'FAIL', 'UNKNOWN'])
def test_coherent_init_normal_snapshot(status):
    assert sum(check.id in IDS for check in registry.CHECKS) == 3
    metadata = {
        KEYS[IDS[0]]: 'true' if status == 'PASS' else 'false' if status == 'FAIL' else None,
        KEYS[IDS[1]]: 'true' if status == 'PASS' else 'false' if status == 'FAIL' else None,
        KEYS[IDS[2]]: '00 19 * * MON' if status == 'PASS' else '' if status == 'FAIL' else None,
    }
    rows = [row(metadata=metadata)]
    if status == 'PASS':
        rows.append(row(NAME + '-deleted', state='DELETED'))
    snapshot, transport = collect({SCOPE: rows})
    output = findings(snapshot)
    assert sum(finding['status'] == status for finding in output) == 3
    assert sum(finding['status'] == 'NOT_APPLICABLE' for finding in output) == (3 if status == 'PASS' else 0)
    assert sum(url.endswith('/instances') for _, url in transport.calls) == 1
