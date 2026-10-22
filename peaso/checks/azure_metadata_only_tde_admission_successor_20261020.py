"""Retain all TDE guards with signed per-wave compiled and source artifacts."""
from copy import deepcopy
import ast
import gzip
import inspect
import hashlib
import json
from pathlib import Path
import sys
import types
from . import azure_nsp_query_cmk_production_tde_successor_20261020 as original
prepared, candidate, azure, producer = original.prepared, original.candidate, original.azure, original.producer
proof, RECEIPT, RECEIPT_SHA256 = original.proof, original.RECEIPT, original.RECEIPT_SHA256
CASES_FILE, IDS = original.CASES_FILE, original.IDS
_runtime, _ORIGINALS = original._runtime, original._ORIGINALS


def reviewed_inputs(root=None):
    """Validate portable source/code identity and native production decisions."""
    from . import azure_function_package_shared_successor_20261020 as shared
    successor = shared.reviewed_delta(root)
    _, _, declarations = prepared.reviewed_inputs(root)
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    try:
        raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
        if proof._hash(raw) != RECEIPT_SHA256:
            raise RuntimeError('production receipt changed')
        receipt = json.loads(raw, object_pairs_hook=proof._pairs)
        if (receipt['ids'] != list(IDS) or receipt['declarations'] != candidate.DECLARATIONS
                or receipt['prepared_receipt_sha256'] != prepared.RECEIPT_SHA256
                or proof._hash(proof._self_source((root / receipt['helper_path']).read_bytes())) != receipt['helper_sha256']):
            raise RuntimeError('production admission source/schema changed')
        _lineage(root, receipt)
        current = _runtime()
        if set(current) != set(_ORIGINALS) or set(current) != set(receipt['functions']):
            raise RuntimeError('production callable set changed')
        compiled = {}
        for name, fn in current.items():
            record = dict(receipt['functions'][name])
            if name == 'peaso.collectors.azure:collect':
                record['source_sha256'] = successor['metadata_only_collect']['current_sha256']
            if name == 'peaso.collectors.azure:_selected':
                transition = shared._private_receipt()['provider_group_callables'][
                    'peaso/collectors/azure.py:_selected']
                if record['source_sha256'] != transition['predecessor_sha256']:
                    raise RuntimeError('production selected-source predecessor changed')
                from peaso import private_reviewed_collector_successor_20261022 as reviewed_epoch
                current_fragment = inspect.getsource(fn)
                epoch_fragment = reviewed_epoch.previous_function_source('peaso/collectors/azure.py', '_selected', current_fragment, root)
                if hashlib.sha256(epoch_fragment.encode()).hexdigest() != transition['current_sha256']:
                    raise RuntimeError('production selected-source epoch changed')
                record['source_sha256'] = hashlib.sha256(current_fragment.encode()).hexdigest()
            path = (root / record['path']).resolve()
            if not path.is_relative_to(root):
                raise RuntimeError('production callable escaped repository')
            source_raw = path.read_bytes()
            matches, source_digest, source = shared.native_artifacts(fn, path, source_raw)
            # Preserve the independent disk reread before source comparison.
            disk = path.read_bytes()
            if (hashlib.sha256(disk).hexdigest() != hashlib.sha256(source_raw).hexdigest()
                    or len(matches) != 1 or matches[0][0]['source_sha256'] != record['source_sha256']
                    or proof._hash(source.encode()) != record['source_sha256']
                    or source_digest != record['source_sha256']):
                raise RuntimeError('production disk callable source changed')
            codes = [code for _, code in matches]
            module = sys.modules.get(fn.__module__)
            if (fn is not _ORIGINALS[name] or module is None or fn.__globals__ is not vars(module)
                    or fn.__qualname__ != record['qualname'] or fn.__closure__
                    or source_digest != record['source_sha256']
                    or len(codes) != 1 or proof._code(fn.__code__) != proof._code(codes[0])
                    or json.dumps(fn.__defaults__, sort_keys=True) != json.dumps(record['defaults'], sort_keys=True)
                    or json.dumps(fn.__kwdefaults__, sort_keys=True) != json.dumps(record['kwdefaults'], sort_keys=True)):
                raise RuntimeError('production executing callable changed')
        if (azure.azure_nsp_query_cmk_runtime_20261020 is not producer
                or candidate is not prepared.candidate or producer is not prepared.producer
                or any(azure.TYPES.count(kind) != 1 or kind in azure.ENDPOINTS for kind in producer.KINDS)
                or not set(producer.KINDS).issubset(azure._selected({}, None))
                or any(azure._selected({}, [kind]) != {kind, 'subscription'} for kind in producer.KINDS)):
            raise RuntimeError('production collector binding changed')
        for row in receipt['fixtures']:
            path = (root / row['path']).resolve()
            if not path.is_relative_to(root) or proof._hash(path.read_bytes()) != row['sha256']:
                raise RuntimeError('production native fixture changed')
        cases = json.loads((root / 'peaso/checks' / CASES_FILE).read_bytes(), object_pairs_hook=proof._pairs)
        if set(cases) != set(IDS):
            raise RuntimeError('production CASES identities changed')
        for spec, fn in declarations:
            case = cases[spec['id']]
            for branch in ('pass', 'fail', 'unknown', 'not_applicable'):
                if branch in case and fn(deepcopy(case[branch]), deepcopy(case[branch + '_index']))[0] != branch.upper():
                    raise RuntimeError('production native decision changed')
            for branch in ('missing', 'malformed'):
                if fn(deepcopy(case[branch]), deepcopy(case['index']))[0] != 'UNKNOWN':
                    raise RuntimeError('production unavailable decision changed')
        return receipt, cases, declarations
    except RuntimeError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
        raise RuntimeError('malformed production admission inputs') from None


def _lineage(root, receipt):
    """Prove this successor changes only the nested owned-database TDE body."""
    for relative, digest in receipt['predecessor_files'].items():
        if proof._hash((root / relative).read_bytes()) != digest:
            raise RuntimeError('TDE predecessor source changed')
    packed = (root / receipt['predecessor_pack']['path']).read_bytes()
    if proof._hash(packed) != receipt['predecessor_pack']['sha256']:
        raise RuntimeError('TDE predecessor pack changed')
    retained = json.loads(gzip.decompress(packed), object_pairs_hook=proof._pairs)['files']
    source = retained['peaso/collectors/azure.py']
    if proof._hash(source['text'].encode()) != source['sha256']:
        raise RuntimeError('TDE retained module changed')
    before_tree = ast.parse(source['text'])
    from . import azure_function_package_shared_successor_20261020 as shared
    binding = shared.reviewed_delta(root)['azure_collect']
    after_source = inspect.getsource(azure.collect)
    after_source = shared.predecessor_azure_collect(after_source, root)
    for addition in binding['exact_additions']:
        if after_source.count(addition) != 1:
            raise RuntimeError('Azure package TDE exact addition changed')
        after_source = after_source.replace(addition, '', 1)
    if proof._hash(after_source.encode()) != binding['predecessor_sha256']:
        raise RuntimeError('Azure package TDE predecessor changed')
    after_tree = ast.parse(after_source)
    before = next(n for n in before_tree.body if isinstance(n, ast.FunctionDef) and n.name == 'collect')
    after = next(n for n in after_tree.body if isinstance(n, ast.FunctionDef) and n.name == 'collect')
    before_source = ''.join(source['text'].splitlines(keepends=True)[before.lineno-1:before.end_lineno])
    if proof._hash(before_source.encode()) != receipt['before_collect_sha256']:
        raise RuntimeError('TDE original collect source changed')
    for function, text, expected in ((before, source['text'], receipt['before_tde_sha256']),
                                     (after, after_source, receipt['after_tde_sha256'])):
        nodes = [n for n in ast.walk(function) if isinstance(n, ast.FunctionDef) and n.name == 'tde']
        if len(nodes) != 1:
            raise RuntimeError('TDE exact nested definition changed')
        node = nodes[0]
        body = ''.join(text.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
        if proof._hash(body.encode()) != expected:
            raise RuntimeError('TDE reviewed nested source changed')
        node.body = [ast.Pass()]
    if ast.dump(before, include_attributes=False) != ast.dump(after, include_attributes=False):
        raise RuntimeError('Azure collect changed outside reviewed TDE body')


def install():
    namespace = dict(vars(original), reviewed_inputs=reviewed_inputs)
    clone = types.FunctionType(original.install.__code__, namespace, original.install.__name__,
                               original.install.__defaults__, original.install.__closure__)
    return clone()


_FUNCTIONS = {name: fn for name, fn in tuple(globals().items())
              if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
