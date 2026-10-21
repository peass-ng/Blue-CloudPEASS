"""Private source adapter for the selected K8s log admission."""
import ast
import hashlib
import json
from pathlib import Path
import sys
import types

from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.collectors import k8s_selected_log_sample_secret_indicators as producer
from . import k8s_annotation_native_admission_20261020 as canonical_proof
from . import k8s_annotation_native_source_successor_20261021 as annotation_successor
from . import k8s_selected_log_sample_admission_20261020 as historical

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / 'peaso/checks/k8s_selected_log_sample_admission_20261020.py'
PRODUCER = ROOT / 'peaso/collectors/k8s_selected_log_sample_secret_indicators.py'
RECEIPT = Path(__file__).with_suffix('.json')
PRIVATE_NAME = 'peaso.checks._k8s_selected_log_source_successor_20261021_namespace'
BEFORE_SHA = '0fe2d51cb83f4126994f1bfaf1eff50c96469c3b1e285c44d78825f48328e9c0'
AFTER_SHA = 'c9c3923d34f35347097d1d7a9c4cc83d8755a0b3c7d7b7dfb059684c9cebd7e3'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _shape(code):
    return json.dumps(canonical_proof._code(code), sort_keys=True, separators=(',', ':'), allow_nan=False)


def _proof():
    row = json.loads(RECEIPT.read_text(), object_pairs_hook=canonical_proof._pairs)
    if (set(row) != {'schema', 'source_sha256', 'guard_sha256', 'guard_receipt_sha256',
                     'annotation_successor_sha256', 'annotation_successor_receipt_sha256',
                     'common_sha256', 'producer_before_sha256', 'producer_after_sha256'}
            or row['schema'] != 'finite-k8s-selected-log-source-successor-v1'
            or _sha(Path(__file__).read_bytes()) != row['source_sha256']
            or _sha(GUARD.read_bytes()) != row['guard_sha256']
            or _sha(GUARD.with_suffix('.json').read_bytes()) != row['guard_receipt_sha256']
            or _sha(Path(annotation_successor.__file__).read_bytes()) != row['annotation_successor_sha256']
            or _sha(Path(annotation_successor.__file__).with_suffix('.json').read_bytes()) != row['annotation_successor_receipt_sha256']
            or _sha(Path(epoch.__file__).read_bytes()) != row['common_sha256']
            or row['producer_before_sha256'] != BEFORE_SHA
            or row['producer_after_sha256'] != AFTER_SHA):
        raise RuntimeError('Selected log successor source or receipt changed')
    module = sys.modules.get(__name__)
    compiled_self = canonical_proof._compiled_source(Path(__file__).read_bytes(), __file__, sys.flags.optimize)
    for name, value in vars(module).items():
        if isinstance(value, types.FunctionType) and value.__globals__ is vars(module):
            matches = [code for record, code in compiled_self if record['qualname'] == name]
            if len(matches) != 1 or _shape(value.__code__) != _shape(matches[0]):
                raise RuntimeError('Selected log successor live function changed: ' + name)
    raw = PRODUCER.read_bytes()
    if (_sha(raw) != AFTER_SHA or sys.modules.get(producer.__name__) is not producer
            or Path(producer.__file__).resolve() != PRODUCER):
        raise RuntimeError('Selected log producer binding changed')
    old = epoch.predecessor_bytes('peaso/collectors/k8s_selected_log_sample_secret_indicators.py',
                                  raw, BEFORE_SHA, ROOT)
    if _sha(old) != BEFORE_SHA:
        raise RuntimeError('Selected log predecessor changed')
    records = canonical_proof._compiled_source(raw, str(PRODUCER), sys.flags.optimize)
    historical._execution(producer.collect, records, expected='collect')
    node, = (n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == 'collect')
    if (producer.collect.__defaults__ != (tuple(ast.literal_eval(v) for v in node.args.defaults) or None)
            or producer.collect.__kwdefaults__ != ({a.arg: ast.literal_eval(v) for a, v in
                zip(node.args.kwonlyargs, node.args.kw_defaults) if v is not None} or None)):
        raise RuntimeError('Selected log collect defaults changed')
    helper = sys.modules.get('peaso.secret_evidence')
    if helper is None or Path(helper.__file__).resolve() != ROOT / 'peaso/secret_evidence.py':
        raise RuntimeError('Selected log helper changed')
    for name in ('scan_with_source', 'target_source'):
        value = vars(producer).get(name)
        if value is not vars(helper).get(name) or not isinstance(value, types.FunctionType):
            raise RuntimeError('Selected log helper binding changed: ' + name)
        epoch._check_helper_import(value, helper, name, ROOT)
    return row, raw, old


def install():
    _, current, before = _proof()
    annotation_successor._self_proof()
    annotation_successor._helper_proof()
    predecessor = sys.modules.get(annotation_successor._PRIVATE_NAME)
    if not isinstance(predecessor, types.ModuleType) or predecessor.install is canonical_proof.install:
        raise RuntimeError('Selected log annotation predecessor absent')
    if PRIVATE_NAME in sys.modules:
        raise RuntimeError('Selected log private namespace occupied')
    clone = types.ModuleType(PRIVATE_NAME)
    clone.__file__ = str(GUARD)
    clone.__package__ = 'peaso.checks'
    sys.modules[PRIVATE_NAME] = clone
    try:
        exec(compile(GUARD.read_bytes(), str(GUARD), 'exec'), vars(clone))
        for name, value in vars(historical).items():
            if isinstance(value, types.FunctionType) and value.__globals__ is vars(historical):
                other = vars(clone).get(name)
                if (not isinstance(other, types.FunctionType) or other.__globals__ is not vars(clone)
                        or _shape(other.__code__) != _shape(value.__code__)
                        or other.__defaults__ != value.__defaults__ or other.__kwdefaults__ != value.__kwdefaults__):
                    raise RuntimeError('Selected log historical clone changed: ' + name)
        original_hash = clone._hash

        def source_hash(value):
            data = value if isinstance(value, bytes) else value.encode()
            if data == current:
                _, raw, old = _proof()
                if raw != current or old != before:
                    raise RuntimeError('Selected log source view changed')
                return original_hash(old)
            return original_hash(value)

        clone._hash = source_hash
        clone.proof = predecessor
        clone.install()
    except BaseException:
        sys.modules.pop(PRIVATE_NAME, None)
        raise
    return clone
