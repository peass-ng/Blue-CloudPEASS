"""Exact combined Dataflow/Batch delta over the sealed Workbench/K8s bridge."""
from copy import deepcopy
import ast
import hashlib
import inspect
import json
from pathlib import Path
import re
import types
import textwrap
from . import gcp_workbench_shared_hook_successor_20261020 as predecessor
original = predecessor.original
PREDECESSOR_REVIEWED_INPUTS = predecessor.PREDECESSOR_REVIEWED_INPUTS
RECEIPT = 'gcp_dataflow_batch_shared_hook_successor_20261020.json'
RECEIPT_SHA256 = 'c6085a12b2468c039c605d314748f02a4963ee01cdf2edbc072f254aa73dc460'


def _self(raw):
    value, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('Selected job shared successor self changed')
    return value


def reviewed_delta(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Selected job shared successor receipt changed')
    receipt = json.loads(raw)
    accepted = predecessor.reviewed_delta(root)
    if receipt['accepted_receipt_sha256'] != predecessor.RECEIPT_SHA256 or set(receipt['shared_functions']) != set(accepted['shared_functions']):
        raise RuntimeError('Selected job shared predecessor changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve(); raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = _self(raw)
        if not path.is_relative_to(root / 'peaso') or hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('Selected job shared reviewed source changed')
    compiled = {}
    for name, row in receipt['successor_functions'].items():
        if globals().get(name) is not _FUNCTIONS[name]:
            raise RuntimeError('Selected job shared callable replaced')
        original._check_function(_FUNCTIONS[name], row, root, compiled)
    return receipt


def check_shared(fn, historical, name, root, compiled, receipt):
    row = receipt['shared_functions'][name]
    accepted = predecessor.reviewed_delta(root)['shared_functions'][name]
    if row['predecessor'] != dict(historical, sha256=accepted['current_sha256']) or accepted['predecessor'] != historical:
        raise RuntimeError('Selected job shared predecessor binding changed')
    restored = inspect.getsource(inspect.unwrap(fn))
    for addition in row['exact_additions']:
        if restored.count(addition) != 1:
            raise RuntimeError('Selected job shared exact additions changed')
        restored = restored.replace(addition, '', 1)
    if (hashlib.sha256(restored.encode()).hexdigest() != accepted['current_sha256']
            or ast.dump(ast.parse(textwrap.dedent(restored)), include_attributes=False) != row['predecessor_ast']):
        raise RuntimeError('Selected job shared changed non-Dataflow/Batch source')
    for addition in accepted['exact_additions']:
        if restored.count(addition) != 1:
            raise RuntimeError('Selected job shared Workbench delta changed')
        restored = restored.replace(addition, '', 1)
    if (hashlib.sha256(restored.encode()).hexdigest() != historical['sha256']
            or ast.dump(ast.parse(textwrap.dedent(restored)), include_attributes=False) != accepted['predecessor_ast']):
        raise RuntimeError('Selected job shared changed historical source')
    original._check_function(fn, dict(historical, sha256=row['current_sha256']), root, compiled)


def prepared_inputs(root, compiled, successor):
    return predecessor.prepared_inputs(root, compiled, predecessor.reviewed_delta(root))


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    successor = reviewed_delta(root)
    raw = (root / 'peaso/checks' / original.RECEIPT).read_bytes()
    if original.prepared._hash(raw) != original.RECEIPT_SHA256:
        raise RuntimeError('metadata runtime receipt changed')
    receipt = json.loads(raw, object_pairs_hook=original.proof._pairs)
    compiled = {}
    runtime = original.runtime
    if (receipt['check'] != original.CHECK or runtime.CHECK != original.CHECK
            or runtime.KIND != original.prepared.producer.KIND or runtime.OPTION != original.prepared.producer.OPTION
            or runtime.GRANT != '_k8s_selected_metadata_grant'
            or json.dumps(receipt['declaration'], sort_keys=True) != json.dumps(original.candidate.DECLARATION, sort_keys=True)
            or runtime._Grant is not original._GRANT_CLASS or runtime._TOKEN is not original._TOKEN
            or runtime.source is not original.prepared.producer or original.candidate is not original.prepared.candidate
            or original.k8s.TYPES.count(runtime.KIND) != 1 or runtime.KIND in original.k8s.ENDPOINTS
            or runtime.KIND not in original.engine.BULK_STREAM_TYPES['k8s'] or runtime.OPTION not in original.validation.OPTIONS):
        raise RuntimeError('metadata runtime metadata/binding changed')
    for name, expected in receipt['sources'].items():
        path = (root / name).resolve()
        raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = original._self(raw)
        if not path.is_relative_to(root) or original.prepared._hash(raw) != expected:
            raise RuntimeError('metadata runtime source changed')
    for row in receipt['fixtures']:
        path = (root / row['path']).resolve()
        if not path.is_relative_to(root / 'peaso/checks') or original.prepared._hash(path.read_bytes()) != row['sha256']:
            raise RuntimeError('metadata packaged runtime fixture changed')
    prepared_inputs(root, compiled, successor)
    current = original._runtime()
    alias = original.__name__ + ':reviewed_inputs'
    if original.reviewed_inputs is reviewed_inputs:
        if alias in current:
            raise RuntimeError('metadata runtime successor alias changed')
        current[alias] = PREDECESSOR_REVIEWED_INPUTS
    elif original.reviewed_inputs not in (PREDECESSOR_REVIEWED_INPUTS, predecessor.reviewed_inputs):
        raise RuntimeError('metadata runtime successor alias replaced')
    if set(current) != set(original._ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('metadata runtime callable set changed')
    for name, fn in current.items():
        if fn is not original._ORIGINALS[name]:
            raise RuntimeError('metadata runtime callable replacement')
        if name in successor['shared_functions']:
            check_shared(fn, receipt['functions'][name], name, root, compiled, successor)
        else:
            original._check_function(fn, receipt['functions'][name], root, compiled)
    cases = json.loads((root / 'peaso/checks' / original.CASES).read_bytes(), object_pairs_hook=original.proof._pairs)
    if set(cases) != {original.CHECK}:
        raise RuntimeError('metadata runtime CASES changed')
    for branch in ('pass', 'fail', 'unknown'):
        if original.candidate.evaluate(deepcopy(cases[original.CHECK][branch]), deepcopy(cases[original.CHECK][branch + '_index']))[0] != branch.upper():
            raise RuntimeError('metadata runtime native witness changed')
    return receipt, cases, deepcopy(original.candidate.DECLARATION), original.candidate.evaluate


def install():
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES as store
    receipt, cases, declaration, function = reviewed_inputs()
    # The immutable authorize/collect functions import this original module path.
    # Route only its reviewed-input entrypoint; the historical object is retained
    # and attested separately, while this actual successor source is self-pinned.
    original.reviewed_inputs = reviewed_inputs
    ident = original.CHECK
    if ident in CHECK_ALIASES or ident in CHECK_ALIASES.values():
        raise RuntimeError('metadata runtime alias collision')
    found = [check for check in CHECKS if check.id == ident]
    if found:
        if len(found) != 1 or not original._INSTALLED:
            raise RuntimeError('metadata runtime collision')
        original._verify(found[0], receipt)
        if json.dumps(store.get(ident), sort_keys=True) != json.dumps(cases[ident], sort_keys=True):
            raise RuntimeError('metadata runtime CASES replacement')
        return
    if ident in store:
        raise RuntimeError('metadata runtime CASES collision')
    before = tuple(CHECKS)
    try:
        register(ident, 'k8s', declaration['category'], original.runtime.KIND, declaration['title'], declaration['severity'],
                 'security_configuration', declaration['remediation'], dependencies=[original.runtime.KIND], allow_incomplete_failure=True)(function)
        check = CHECKS[-1]
        setattr(check.evaluate, original.MARK, ident)
        original._verify(check, receipt)
        store[ident] = deepcopy(cases[ident])
        original._INSTALLED = (check.evaluate, original.proof._bindings(check.evaluate)['checked'])
    except Exception:
        CHECKS[:] = before
        store.pop(ident, None)
        raise

_FUNCTIONS = {name: fn for name, fn in tuple(globals().items()) if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
