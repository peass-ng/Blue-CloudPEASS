"""Trusted native parity, immutable predecessor and actual hosted cold routes."""
import hashlib
import ast
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from peaso.server import native_policy_validation as predecessor
from peaso.server import native_policy_validation_static_20261020 as successor

ROOT = Path(__file__).resolve().parents[1]
PREDECESSOR_SHA256 = 'c84159d8cc96b092aeea28db399c31a6c7b09bff90502e9b3e76cb2bb79791bd'


def result(function, value, module, scoped=False):
    try:
        function(value, module, individually_scoped=scoped)
    except Exception as error:
        return [type(error).__name__, str(error)]
    return None


def cases(roster):
    # Every finite manifest ID against every module detects both accidental
    # unions and accidental subsets; only the exact source_module may accept.
    all_ids = sorted(set().union(*roster.values()))
    for module in sorted(roster):
        for cid in all_ids + ['unreviewed.invalid', 'azure.storage.https_only']:
            yield [{cid: {}}, module, False]
        cid = sorted(roster[module])[0]
        for value in (None, False, True, 0, 1, '', 'x', [], {}, [1], {cid: None}, {cid: []}, {cid: 1},
                      {cid: {'nested': [None, True, 1, 0.5, 'normative']}}, {cid: {'x': 'y' * 8193}},
                      {cid: {'x': '\x00'}}, {cid: {'x': [1] * 257}},
                      {cid: {'x' * 257: 'bad-key'}}, {cid: {str(i): 0 for i in range(257)}}):
            yield [value, module, False]
        for scope in ('/subscriptions/customer', '/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                      '/subscriptions/' + 'x' * 128, '/subscriptions/' + 'x' * 129, '*', '', None, 0):
            for status in ('collected', 'missing', None, True):
                yield [{cid: {'status': status, 'scope': scope}}, module, True]
        for value in ({cid: {}}, {cid: {'scope': '/subscriptions/customer'}},
                      {cid: {'status': 'collected'}}, {cid: []}):
            yield [value, module, True]
        nested = {}
        for _ in range(16):
            nested = {'x': nested}
        yield [{cid: nested}, module, False]
    yield [{'unreviewed.invalid': {}}, 'unknown-module', False]


def test_exact_roster_and_all_finite_id_decisions_match_trusted_native_subprocess():
    roster = successor.module_ids()
    corpus = list(cases(roster))
    code = '''
import json, sys
from peaso.checks.bulk_pending import MANIFEST
from peaso.server.native_policy_validation import _check_review_map
assert _check_review_map.__module__ == 'peaso.server.native_policy_validation'
roster = {name: sorted(cid for cid, contract in MANIFEST['checks'].items()
                      if contract['source_module'] == name) for name in MANIFEST['modules']}
outcomes = []
for value, module, scoped in json.load(sys.stdin):
    try:
        _check_review_map(value, module, individually_scoped=scoped)
    except Exception as error:
        outcomes.append([type(error).__name__, str(error)])
    else:
        outcomes.append(None)
print(json.dumps({'roster': roster, 'outcomes': outcomes}))
'''
    trusted = subprocess.run([sys.executable, '-c', code], input=json.dumps(corpus), cwd=ROOT,
                             capture_output=True, text=True, timeout=180,
                             env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', AWS_EC2_METADATA_DISABLED='true'))
    assert trusted.returncode == 0, trusted.stderr
    expected = json.loads(trusted.stdout)
    assert expected['roster'] == {name: sorted(ids) for name, ids in roster.items()}
    actual = [result(successor.check_review_map, *case) for case in corpus]
    assert actual == expected['outcomes']
    assert len(corpus) == 34161


def test_install_idempotency_and_exact_predecessor_bytes():
    path = ROOT / 'peaso/server/native_policy_validation.py'
    assert hashlib.sha256(path.read_bytes()).hexdigest() == PREDECESSOR_SHA256
    original = predecessor._check_review_map
    try:
        successor.install()
        successor.install()
        assert predecessor._check_review_map is successor.check_review_map
        assert hashlib.sha256(path.read_bytes()).hexdigest() == PREDECESSOR_SHA256
    finally:
        predecessor._check_review_map = original


def test_exact_roster_is_typed_and_immutable():
    roster = successor.module_ids()
    assert len(roster) == 56
    assert sum(map(len, roster.values())) == 552
    assert all(type(name) is str and type(ids) is frozenset
               and all(type(cid) is str for cid in ids) for name, ids in roster.items())
    with pytest.raises(TypeError):
        roster['compliance_new_sw16'] = frozenset({'unreviewed.invalid'})


def test_owner_fixture_matches_immutable_accepted_hosted_intake_source():
    fixture = json.loads(Path(__file__).with_name('connector_owner_fixture_20261020.json').read_text())
    source = ROOT / 'tests' / fixture['source_path']
    assert hashlib.sha256(source.read_bytes()).hexdigest() == fixture['source_sha256']
    tree = ast.parse(source.read_text())
    auth = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'AUTH' for target in node.targets))
    test = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == fixture['test'])
    accepted = test.decorator_list[0].args[1].elts
    selected = []
    for entry in accepted:
        try:
            provider, options = ast.literal_eval(entry)
        except (ValueError, TypeError):
            continue
        if provider == 'azure' and set(options.get('compliance_policy', {})) == {'sw16'}:
            selected.append(options)
    assert selected == [fixture['body']['options']]
    assert fixture['body']['auth'] == auth['azure']


@pytest.mark.parametrize('mode', ['missing', 'corrupt', 'oversized'])
def test_roster_fails_closed_without_native_fallback(tmp_path, monkeypatch, mode):
    path = tmp_path / 'bulk_pending.json'
    if mode == 'corrupt':
        path.write_text('{}')
    elif mode == 'oversized':
        path.write_bytes(b' ' * (successor.MAX_MANIFEST_BYTES + 1))
    successor.module_ids.cache_clear()
    monkeypatch.setattr(successor, 'MANIFEST_PATH', path)
    try:
        with pytest.raises(ValueError):
            successor.module_ids()
    finally:
        successor.module_ids.cache_clear()


def test_real_hosted_post_patch_all_ids_without_native_registry_imports():
    proof = subprocess.run([sys.executable, str(Path(__file__).with_name('probe_connector_static_20261020.py'))],
                           cwd=ROOT, capture_output=True, text=True, timeout=180,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    assert proof.returncode == 0, proof.stderr
    evidence = json.loads(proof.stdout)
    assert evidence['native_modules_loaded'] == []
    assert evidence['network_attempts'] == 0
    assert evidence['auth_mode'] == 'cognito'
    assert evidence['exact_owner_fixture']
    assert evidence['owner_check_review_map_calls'] == 2
    assert evidence['counts']['accepted_post'] == evidence['counts']['accepted_patch'] == 52
    assert evidence['counts']['rejected_post'] == evidence['counts']['rejected_patch'] == 2202


def test_native_registrar_still_admits_every_manifest_id_after_api_rebinding():
    code = '''
import json, tempfile
from pathlib import Path
from peaso.auth import Identity
from peaso.server.app import create_app
from peaso.server.config import Settings
class OfflineIdentity:
    def authenticate(self, authorization):
        return Identity('same-process-native-admission', True)
with tempfile.TemporaryDirectory(prefix='peaso-api-native-parity-') as temporary:
    directory = Path(temporary)
    create_app(Settings(state_dir=directory/'state', identity_dir=directory/'identity',
                        auth_mode='cognito'), authenticator=OfflineIdentity())
    from peaso.checks import CHECKS
    from peaso.checks.bulk_pending import MANIFEST
    from peaso.server import native_policy_validation
    from peaso.server.native_policy_validation_static_20261020 import check_review_map
    assert native_policy_validation._check_review_map is check_review_map
    assert set(MANIFEST['checks']) <= {check.id for check in CHECKS}
    print(json.dumps({'registered_checks': len(CHECKS), 'bulk_checks': len(MANIFEST['checks'])}))
'''
    native = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True,
                            timeout=180, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                                                  PEASO_STORAGE='sqlite', AWS_EC2_METADATA_DISABLED='true'))
    assert native.returncode == 0, native.stderr
    assert json.loads(native.stdout)['bulk_checks'] == 552
