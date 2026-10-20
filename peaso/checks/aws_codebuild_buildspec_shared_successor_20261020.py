"""Exact CodeBuild-only shared-source successor over original WB/DF/K8s guards."""
from copy import deepcopy
import ast
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import re
import types
import textwrap
from . import gcp_dataflow_batch_shared_hook_successor_20261020 as predecessor
original = predecessor.original
PREDECESSOR_REVIEWED_INPUTS = predecessor.PREDECESSOR_REVIEWED_INPUTS
RECEIPT = 'aws_codebuild_buildspec_shared_successor_20261020.json'
RECEIPT_SHA256 = '3f850167f2dfc92c78222f38ae48b7bedb0b102e13578a9bb9508df0000cdcce'


def _self(raw):
    result, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('CodeBuild shared successor self changed')
    return result


def reviewed_delta(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('CodeBuild shared successor receipt changed')
    receipt = json.loads(raw)
    accepted = predecessor.reviewed_delta(root)
    if receipt['accepted_receipt_sha256'] != predecessor.RECEIPT_SHA256:
        raise RuntimeError('CodeBuild shared predecessor changed')
    archive = json.loads(gzip.decompress((root / receipt['archive']).read_bytes()))
    for name, row in archive['files'].items():
        old = bytes.fromhex(row['hex'])
        if hashlib.sha256(old).hexdigest() != row['sha256']:
            raise RuntimeError('CodeBuild exact predecessor archive changed')
        if name.startswith('peaso/checks/') and not name.endswith('/__init__.py'):
            if (root / name).read_bytes() != old:
                raise RuntimeError('CodeBuild historical guard bytes changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve(); data = path.read_bytes()
        if name == receipt['helper_path']:
            data = _self(data)
        if not path.is_relative_to(root / 'peaso') or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('CodeBuild shared source changed')
    if set(receipt['shared_functions']) != set(accepted['shared_functions']) | {'aws.collect'}:
        raise RuntimeError('CodeBuild shared function set changed')
    compiled = {}
    for name, row in receipt['successor_functions'].items():
        if globals().get(name) is not _FUNCTIONS[name]:
            raise RuntimeError('CodeBuild shared callable replaced')
        original._check_function(_FUNCTIONS[name], row, root, compiled)
    from . import aws_codebuild_buildspec_s3_successor_20261020 as s3
    for name, row in receipt['s3_functions'].items():
        if getattr(s3, name) is not s3._FUNCTIONS[name]:
            raise RuntimeError('CodeBuild S3 successor callable replaced')
        original._check_function(getattr(s3, name), row, root, compiled)
    return receipt


def check_aws(function, expected):
    """The original S3 code proof remains in force around exact AWS additions."""
    from . import aws_s3_selected_source_admission_20261020 as s3
    receipt = reviewed_delta()
    row = receipt['shared_functions']['aws.collect']
    if row['predecessor_sha256'] != expected['sha256']:
        raise RuntimeError('CodeBuild AWS predecessor changed')
    restored = inspect.getsource(function)
    for addition in row['exact_additions']:
        if restored.count(addition) != 1:
            raise RuntimeError('CodeBuild AWS exact branch changed')
        restored = restored.replace(addition, '', 1)
    if hashlib.sha256(restored.encode()).hexdigest() != expected['sha256']:
        raise RuntimeError('CodeBuild changed non-CodeBuild AWS source')
    if s3.proof(function) != dict(expected, sha256=row['current_sha256']):
        raise RuntimeError('CodeBuild AWS executing callable changed')


def check_shared(fn, historical, name, root, compiled, receipt):
    row = receipt['shared_functions'][name]
    accepted = predecessor.reviewed_delta(root)['shared_functions'][name]
    if row['predecessor_sha256'] != accepted['current_sha256']:
        raise RuntimeError('CodeBuild shared predecessor binding changed')
    restored = inspect.getsource(inspect.unwrap(fn))
    for addition in row['exact_additions']:
        if restored.count(addition) != 1:
            raise RuntimeError('CodeBuild shared exact branch changed')
        restored = restored.replace(addition, '', 1)
    if (hashlib.sha256(restored.encode()).hexdigest() != accepted['current_sha256']
            or ast.dump(ast.parse(textwrap.dedent(restored)), include_attributes=False) != row['predecessor_ast']):
        raise RuntimeError('CodeBuild shared non-CodeBuild source changed')
    # Preserve both earlier exact-delta proofs, without replacing their functions.
    for addition in accepted['exact_additions']:
        if restored.count(addition) != 1:
            raise RuntimeError('CodeBuild inherited job delta changed')
        restored = restored.replace(addition, '', 1)
    wb = predecessor.predecessor.reviewed_delta(root)['shared_functions'][name]
    if hashlib.sha256(restored.encode()).hexdigest() != wb['current_sha256']:
        raise RuntimeError('CodeBuild inherited Workbench source changed')
    for addition in wb['exact_additions']:
        if restored.count(addition) != 1:
            raise RuntimeError('CodeBuild inherited Workbench delta changed')
        restored = restored.replace(addition, '', 1)
    if hashlib.sha256(restored.encode()).hexdigest() != historical['sha256']:
        raise RuntimeError('CodeBuild historical shared source changed')
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


def install_dataflow(admission):
    """Only reviewed shared admission alias changes; its 119 functions stay exact."""
    receipt = reviewed_delta()
    if admission.shared not in (predecessor, __import__(__name__, fromlist=[''])):
        raise RuntimeError('CodeBuild Dataflow shared alias replaced')
    old = admission.shared
    admission.shared = __import__(__name__, fromlist=[''])
    try:
        admission.install()
    except Exception:
        admission.shared = old
        raise


def install_bundle():
    """Preflight before registry/alias mutation, then roll back this whole wave."""
    from . import CHECKS
    from .fixtures import CASES
    from . import gcp_workbench_source_runtime_admission_20261020 as workbench
    from . import gcp_dataflow_batch_source_runtime_admission_20261020 as dataflow
    from . import aws_codebuild_buildspec_runtime_admission_20261020 as codebuild
    # This validation has no registry or shared-alias writes.
    codebuild.reviewed_inputs()
    ids = {original.CHECK, *workbench.CHECK_IDS, *dataflow.runtime.CHECKS, codebuild.runtime.CHECK}
    before = tuple(CHECKS)
    old_cases = {ident: deepcopy(CASES[ident]) for ident in ids if ident in CASES}
    old_reviewed, old_installed, old_shared = original.reviewed_inputs, original._INSTALLED, dataflow.shared
    try:
        install()
        workbench.install()
        install_dataflow(dataflow)
        codebuild.install()
    except Exception:
        CHECKS[:] = before
        for ident in ids:
            if ident in old_cases:
                CASES[ident] = old_cases[ident]
            else:
                CASES.pop(ident, None)
        original.reviewed_inputs, original._INSTALLED, dataflow.shared = old_reviewed, old_installed, old_shared
        raise

_FUNCTIONS = {name: fn for name, fn in tuple(globals().items()) if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
