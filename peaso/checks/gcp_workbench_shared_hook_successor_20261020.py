"""Preserve sealed K8s admission across exact reviewed GCP Workbench additions.

No predecessor function, receipt or runtime grant is modified. Three shared
functions require source/bytecode validation plus exact predecessor reconstruction.
"""
from copy import deepcopy
import ast
import hashlib
import inspect
import gzip
import json
from pathlib import Path
import re
import types
import textwrap

from . import k8s_selected_metadata_runtime_admission_20261020 as original

RECEIPT = 'gcp_workbench_shared_hook_successor_20261020.json'
PREDECESSOR_REVIEWED_INPUTS = original.reviewed_inputs

RECEIPT_SHA256 = 'd6dc0461e17473bc437eb9a9f68c7e39103c6e6dcdccbc84ef469eda88002593'


def _self(raw):
    value, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$",
        b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('Workbench shared successor self binding changed')
    return value


def reviewed_delta(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Workbench shared successor receipt changed')
    receipt = json.loads(raw)
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = _self(raw)
        if not path.is_relative_to(root / 'peaso') or hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('Workbench shared successor source changed')
    if set(receipt['shared_functions']) != {'engine._request', 'engine.collect_snapshot', 'validation.validate_connector'}:
        raise RuntimeError('Workbench shared successor function set changed')
    compiled = {}
    for name, row in receipt['successor_functions'].items():
        if globals().get(name) is not _FUNCTIONS[name]:
            raise RuntimeError('Workbench shared successor callable replaced')
        original._check_function(_FUNCTIONS[name], row, root, compiled)
    return receipt


def check_shared(fn, predecessor, name, root, compiled, receipt):
    row = (receipt['prepared_functions'] if name.startswith('shared:') else receipt['shared_functions'])[name]
    source = inspect.getsource(inspect.unwrap(fn))
    if row['predecessor'] != predecessor:
        raise RuntimeError('Workbench shared successor predecessor changed')
    restored = source
    for addition in row['exact_additions']:
        if restored.count(addition) != 1:
            raise RuntimeError('Workbench shared successor delta changed')
        restored = restored.replace(addition, '', 1)
    if (hashlib.sha256(restored.encode()).hexdigest() != predecessor['sha256']
            or ast.dump(ast.parse(textwrap.dedent(restored)), include_attributes=False) != row['predecessor_ast']):
        raise RuntimeError('Workbench shared successor changed non-Workbench source')
    # The predecessor gate checks actual code against compiled current source,
    # globals, defaults and the new hash; reconstruction above checks old bytes.
    current = dict(predecessor, sha256=row['current_sha256'])
    original._check_function(fn, current, root, compiled)


def prepared_inputs(root, compiled, successor):
    """Unchanged prepared proof, with one explicitly attested disjoint router delta."""
    prepared, proof = original.prepared, original.proof
    raw = (root / 'peaso/checks' / prepared.RECEIPT).read_bytes()
    if prepared._hash(raw) != prepared.RECEIPT_SHA256:
        raise RuntimeError('metadata predecessor receipt changed')
    receipt = json.loads(raw, object_pairs_hook=proof._pairs)
    if json.dumps(receipt['schema'], sort_keys=True) != json.dumps(prepared._schema(), sort_keys=True):
        raise RuntimeError('metadata predecessor schema changed')
    for relative, expected in receipt['sources'].items():
        path = (root / relative).resolve()
        raw = path.read_bytes()
        if relative == receipt['helper_path']:
            raw = prepared._self(raw)
        if not path.is_relative_to(root) or prepared._hash(raw) != expected:
            raise RuntimeError('metadata predecessor source changed')
    assets = json.loads(gzip.decompress((root / 'peaso/checks' / original.ASSETS).read_bytes()), object_pairs_hook=proof._pairs)
    required = [row for row in receipt['fixtures'] if row['path'].startswith('peaso/checks/')
                or row['path'].endswith('/k8s_selected_metadata_secret_native_20261020.json.gz')]
    if set(assets) != {row['path'] for row in required}:
        raise RuntimeError('metadata packaged predecessor assets changed')
    for row in required:
        entry = assets[row['path']]
        if entry['sha256'] != row['sha256'] or prepared._hash(bytes.fromhex(entry['hex'])) != row['sha256']:
            raise RuntimeError('metadata packaged predecessor fixture changed')
    current = prepared._runtime()
    if set(current) != set(prepared._ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('metadata predecessor callable set changed')
    for name, fn in current.items():
        if fn is not prepared._ORIGINALS[name] or inspect.unwrap(fn) is not prepared._INNERS[name]:
            raise RuntimeError('metadata predecessor callable replacement')
        if name in successor['prepared_functions']:
            check_shared(fn, receipt['functions'][name], name, root, compiled, successor)
        else:
            original._check_function(fn, receipt['functions'][name], root, compiled)
        if isinstance(fn, types.FunctionType) and (fn.__code__ is not prepared._CODES[name] or fn.__closure__ != prepared._CLOSURES[name]):
            raise RuntimeError('metadata predecessor wrapper replacement')
    prepared._clone_bindings()
    from peaso.collectors import k8s_network_extensions as network
    if (json.dumps(network.RESOURCES, sort_keys=True) != json.dumps(successor['network_resources'], sort_keys=True)
            or network.BY_ENDPOINT != {(group, plural): kind for kind, (groups, plural, ns) in network.RESOURCES.items() for group in groups}):
        raise RuntimeError('metadata network router map changed')
    original._check_function(network.match, successor['network_matcher'], root, compiled)
    for kind, (version, plural, _) in prepared.producer.NATIVE_KINDS.items():
        prefix = '/api/v1' if version == 'v1' else '/apis/' + version
        for path in (prefix + '/namespaces/review/' + plural,
                     prefix + '/namespaces/review/' + plural + '/selected-name'):
            if network.match(path) is not None:
                raise RuntimeError('metadata selected routes overlap network router')


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
    elif original.reviewed_inputs is not PREDECESSOR_REVIEWED_INPUTS:
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
