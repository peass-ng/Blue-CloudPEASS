"""Finite private-source adapter for eight historical kubelet ConfigMap checks.

The canonical admission module and annotation proof stay untouched.  Exact
source clones execute in a private module namespace after the current collector
and the predecessor projection have passed the annotation successor.
"""
import hashlib
import json
from pathlib import Path
import sys
import types

from . import k8s_annotation_native_admission_20261020 as canonical_proof
from . import k8s_annotation_native_source_successor_20261021 as annotation_successor
from . import k8s_kubelet_configmap_admission_20261020 as historical

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / 'peaso/checks/k8s_kubelet_configmap_admission_20261020.py'
RECEIPT = Path(__file__).with_suffix('.json')
PRIVATE_NAME = 'peaso.checks._k8s_kubelet_configmap_source_successor_20261021_namespace'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _shape(code):
    return json.dumps(canonical_proof._code(code), sort_keys=True,
                      separators=(',', ':'), allow_nan=False)


def _receipt():
    row = json.loads(RECEIPT.read_text(), object_pairs_hook=canonical_proof._pairs)
    required = {'schema', 'source_sha256', 'guard_sha256', 'guard_receipt_sha256',
                'annotation_successor_sha256', 'annotation_successor_receipt_sha256',
                'helper_sha256', 'ids'}
    if (set(row) != required or row['schema'] != 'finite-k8s-kubelet-source-successor-v1'
            or row['ids'] != list(historical.IDS)
            or _sha(Path(__file__).read_bytes()) != row['source_sha256']
            or _sha(GUARD.read_bytes()) != row['guard_sha256']
            or _sha((GUARD.with_name(historical.RECEIPT)).read_bytes()) != row['guard_receipt_sha256']
            or _sha(Path(annotation_successor.__file__).read_bytes()) != row['annotation_successor_sha256']
            or _sha(Path(annotation_successor.__file__).with_suffix('.json').read_bytes()) != row['annotation_successor_receipt_sha256']
            or _sha(annotation_successor.source_epoch.predecessor_bytes('peaso/secret_evidence.py', (ROOT / 'peaso/secret_evidence.py').read_bytes(), row['helper_sha256'], ROOT)) != row['helper_sha256']):
        raise RuntimeError('Kubelet source successor or receipt changed')
    caller = (ROOT / 'peaso/checks/__init__.py').read_text()
    hunk = ('from . import k8s_kubelet_configmap_source_successor_20261021\n'
            'k8s_kubelet_configmap_source_successor_20261021.install()')
    if caller.count(hunk) != 1:
        raise RuntimeError('Kubelet source successor initializer call changed')
    source = Path(__file__).read_bytes()
    compiled = canonical_proof._compiled_source(source, str(Path(__file__)), sys.flags.optimize)
    module = sys.modules[__name__]
    for name, fn in vars(module).items():
        if not isinstance(fn, types.FunctionType) or fn.__globals__ is not vars(module):
            continue
        matches = [code for record, code in compiled if record['qualname'] == name]
        if len(matches) != 1 or _shape(fn.__code__) != _shape(matches[0]):
            raise RuntimeError('Kubelet source successor live function changed: ' + name)
    return row


def _clone_guard():
    if PRIVATE_NAME in sys.modules:
        raise RuntimeError('Kubelet private namespace already occupied')
    source = GUARD.read_bytes()
    module = types.ModuleType(PRIVATE_NAME)
    module.__file__ = str(GUARD)
    module.__package__ = 'peaso.checks'
    sys.modules[PRIVATE_NAME] = module
    try:
        exec(compile(source, str(GUARD), 'exec'), vars(module))
        for name, original in vars(historical).items():
            if not isinstance(original, types.FunctionType) or original.__globals__ is not vars(historical):
                continue
            clone = vars(module).get(name)
            if (not isinstance(clone, types.FunctionType) or clone.__globals__ is not vars(module)
                    or _shape(clone.__code__) != _shape(original.__code__)
                    or clone.__defaults__ != original.__defaults__
                    or clone.__kwdefaults__ != original.__kwdefaults__):
                raise RuntimeError('Kubelet historical guard clone changed: ' + name)
        return module
    except BaseException:
        sys.modules.pop(PRIVATE_NAME, None)
        raise


def install():
    _receipt()
    annotation_successor._self_proof()
    raw, _ = annotation_successor._source_proofs()
    annotation_successor._current_functions(raw)
    predecessor = sys.modules.get(annotation_successor._PRIVATE_NAME)
    if not isinstance(predecessor, types.ModuleType) or predecessor.install is canonical_proof.install:
        raise RuntimeError('Kubelet annotation predecessor proof absent')
    if predecessor._reviewed_inputs()[0]['ids'] != list(canonical_proof.IDS):
        raise RuntimeError('Kubelet annotation predecessor lineage changed')
    clone = _clone_guard()
    # Only the private clone sees the source-aware annotation proof. Its
    # canonical counterpart keeps the original module binding and function IDs.
    clone.proof = predecessor
    try:
        clone.install()
    except BaseException:
        sys.modules.pop(PRIVATE_NAME, None)
        raise
    return clone
