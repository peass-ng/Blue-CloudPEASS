"""Atomic exact-source admission for five existing native annotation criteria.

No historical CASES or Check metadata is changed. Existing safe/checked,
provider-managed applicability and Claude native-field wrappers are cloned with
fresh closure cells; only the innermost criterion is replaced.
"""
import ast
from copy import deepcopy
from dataclasses import replace
from functools import lru_cache
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import sys
import types

IDS = (
    'k8s.claude.ingress.no_nginx_snippets',
    'k8s.claude.ingress.no_nginx_snippet_alias',
    'k8s.claude.ingress.no_nginx_snippet_lua',
    'k8s.claude.podsecuritypolicy.default_seccomp_profile',
    'k8s.claude.podsecuritypolicy.security_services_hardening',
)
MARK = '_k8s_annotation_native_admission_20261020'
PORTABLE_RECEIPT = 'k8s_annotation_native_admission_selected_metadata_successor_20261020.json'
_PREDECESSORS = {}
SOURCE_PATHS = (
    'peaso/checks/k8s_annotation_native_admission_20261020.py',
    'peaso/checks/k8s_annotation_indicators_review_20261020.py',
    'peaso/collectors/k8s_annotation_indicators_20261020.py',
    'peaso/collectors/k8s_legacy_psp_planner_20261020.py',
    'peaso/checks/k8s_managed.py',
)
SCHEMA_KEYS = ('MARKER', 'CONTEXT', 'SCHEMA', 'FLAGS', 'TYPES', 'MAX_ANNOTATIONS',
               'MAX_ANNOTATION_BYTES', 'MAX_PAGE_BYTES', 'MAX_NATIVE_PAGES')
CALLABLES = {
    'peaso.checks.k8s_annotation_indicators_review_20261020': ('evaluate', '_native_flags', 'evaluate_for'),
    'peaso.collectors.k8s_annotation_indicators_20261020': ('digest', 'identity', 'project', 'collection_context', 'pages'),
    'peaso.collectors.k8s': ('_sanitize', '_native', '_pages', 'collect'),
    'peaso.engine': ('plan_collection',),
    'peaso.checks.facts': ('guard',),
}


def _hash(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def _constant(value):
    if isinstance(value, types.CodeType):
        return {'code': _code(value)}
    if isinstance(value, tuple):
        return {'tuple': [_constant(v) for v in value]}
    if isinstance(value, frozenset):
        return {'frozenset': sorted((_constant(v) for v in value), key=repr)}
    if value is None or type(value) in (str, int, bool, float):
        return value
    if isinstance(value, bytes):
        return {'bytes': value.hex()}
    if value is Ellipsis:
        return {'literal': 'Ellipsis'}
    if isinstance(value, slice):
        return {'slice': [_constant(value.start), _constant(value.stop), _constant(value.step)]}
    if isinstance(value, complex):
        return {'complex': [value.real, value.imag]}
    raise RuntimeError('Unreviewed annotation callable constant')


def _code(code):
    # Compare only against code freshly compiled ON THIS interpreter. Nothing
    # interpreter-specific is persisted in the portable receipt. Python3.10
    # represents exception routing in bytecode and has no co_exceptiontable.
    return {'name': code.co_name, 'bytecode': code.co_code.hex(), 'constants': [_constant(c) for c in code.co_consts],
        'names': list(code.co_names), 'variables': list(code.co_varnames),
        'freevars': list(code.co_freevars), 'cellvars': list(code.co_cellvars),
        'args': [code.co_argcount, code.co_posonlyargcount, code.co_kwonlyargcount],
        'flags': code.co_flags, 'stacksize': code.co_stacksize, 'nlocals': code.co_nlocals,
        'exceptiontable': getattr(code, 'co_exceptiontable', b'').hex()}


def _ast_form(value):
    """Stable source structure across supported AST versions, without offsets."""
    if isinstance(value, ast.AST):
        return {'node': type(value).__name__, 'fields': {
            key: _ast_form(member) for key, member in ast.iter_fields(value)
            if key not in ('lineno', 'col_offset', 'end_lineno', 'end_col_offset')
            and not (key == 'type_params' and not member)
            and not (key == 'is_lazy' and type(member) in (bool, int) and member == 0)}}
    if isinstance(value, list):
        return [_ast_form(v) for v in value]
    return _constant(value)


def _definitions(tree, source):
    """Derive lexical qualnames without the Python3.11 co_qualname attribute."""
    lines = source.splitlines(keepends=True); records = {}
    def visit(node, prefix=''):
        child_prefix = prefix
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = prefix + node.name
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                key = (node.name, start)
                if key in records:
                    raise RuntimeError('Ambiguous annotation source definition')
                records[key] = {'qualname': name,
                    'source_sha256': _hash(''.join(lines[start - 1:node.end_lineno])),
                    'ast_sha256': _hash(json.dumps(_ast_form(node), sort_keys=True))}
                child_prefix = name + '.<locals>.'
            else:
                child_prefix = name + '.'
        for child in ast.iter_child_nodes(node):
            visit(child, child_prefix)
    visit(tree)
    return records


@lru_cache(maxsize=32)
def _compiled_source(raw, filename, optimize):
    """Compile complete verified source for lexical context; NEVER execute it."""
    text = raw.decode('utf-8')
    tree = ast.parse(text, filename=filename, type_comments=True)
    definitions = _definitions(tree, text)
    compiled = compile(tree, filename, 'exec', dont_inherit=True, optimize=optimize)
    records = []
    def visit(code):
        definition = definitions.get((code.co_name, code.co_firstlineno))
        if definition is not None:
            records.append((definition, code))
        for member in code.co_consts:
            if isinstance(member, types.CodeType):
                visit(member)
    visit(compiled)
    return records


def _verified_source(relative, raw, expected):
    """Verify whole dedicated files or exact shared top-level AST ancestors.

    Shared surrounding code is parsed only to locate reviewed definitions;
    only hash-verified selected source is compiled, and it is never executed.
    """
    if isinstance(expected, str):
        if _hash(raw) != expected:
            raise RuntimeError('Reviewed annotation callable changed: source bytes')
        return raw
    if (not isinstance(expected, dict) or set(expected) != {'mode', 'functions', 'future_imports', 'imports'}
            or expected['mode'] != 'top_level_ancestors' or not expected['functions']
            or not isinstance(expected['functions'], dict)):
        raise RuntimeError('Malformed annotation scoped source receipt')
    text = raw.decode('utf-8'); lines = text.splitlines(keepends=True)
    tree = ast.parse(text, filename=relative, type_comments=True)
    futures = []; definitions = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == '__future__':
            futures.append(''.join(lines[node.lineno-1:node.end_lineno]))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in expected['functions']:
            if node.name in definitions:
                raise RuntimeError('Reviewed annotation callable changed: duplicate source ancestor')
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            unit = ''.join(lines[start-1:node.end_lineno])
            proof = {'source_sha256': _hash(unit), 'ast_sha256': _hash(json.dumps(_ast_form(node), sort_keys=True))}
            if proof != expected['functions'][node.name]:
                raise RuntimeError('Reviewed annotation callable changed: source ancestor')
            definitions[node.name] = unit
    names = {node.id for node in ast.walk(ast.parse('\n'.join(definitions.values()))) if isinstance(node, ast.Name)}
    imports = []; imported_names = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)) and not (isinstance(node, ast.ImportFrom) and node.module == '__future__'):
            bindings = {alias.asname or alias.name.split('.')[0] for alias in node.names}
            if names.intersection(bindings):
                imported_names.update(bindings)
                imports.append(''.join(lines[node.lineno-1:node.end_lineno]))
    def rebound(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return node.name in imported_names  # Do not inspect unexecuted bodies.
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            return node.id in imported_names
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            value = node.value
            while isinstance(value, ast.Attribute):
                value = value.value
            return isinstance(value, ast.Name) and value.id in imported_names
        return any(rebound(child) for child in ast.iter_child_nodes(node))
    if any(rebound(node) for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))):
        raise RuntimeError('Reviewed annotation callable changed: imported binding rebound')
    if ([{'source_sha256': _hash(unit)} for unit in imports] != expected['imports']
            or [{'source_sha256': _hash(unit)} for unit in futures] != expected['future_imports']
            or set(definitions) != set(expected['functions'])):
        raise RuntimeError('Reviewed annotation callable changed: source ancestors or future imports')
    return ('\n'.join(futures + imports + [definitions[name] for name in sorted(definitions)])).encode()


def _source_receipt():
    return json.loads(Path(__file__).with_name(PORTABLE_RECEIPT).read_text(), object_pairs_hook=_pairs)


def _trusted_definition(function):
    """Verify source bytes before any AST compilation or loaded-code comparison."""
    root = Path(__file__).resolve().parents[2]
    module_name = function.__globals__.get('__name__')
    module = sys.modules.get(module_name)
    if module is None or vars(module) is not function.__globals__:
        raise RuntimeError('Reviewed annotation callable changed: global binding')
    filename = function.__globals__.get('__file__')
    path = Path(filename).resolve() if isinstance(filename, str) else root.parent
    if not path.is_relative_to(root):
        raise RuntimeError('Reviewed annotation callable changed: source identity')
    relative = str(path.relative_to(root))
    receipt = _source_receipt()
    expected = receipt['compiled_sources'].get(relative)
    if expected is None:
        raise RuntimeError('Reviewed annotation callable changed: source identity')
    raw = _verified_source(relative, path.read_bytes(), expected)
    # Python equality conflates False, 0 and 0.0. Canonical JSON retains
    # their distinct constant types, including recursively nested code.
    def shape(code):
        return json.dumps(_code(code), sort_keys=True, separators=(',', ':'), allow_nan=False)
    code = function.__code__
    try:
        actual = shape(code)
        matches = [(record, compiled) for record, compiled in
            _compiled_source(raw, str(path), sys.flags.optimize)
            if compiled.co_name == code.co_name and shape(compiled) == actual]
    except (TypeError, ValueError) as error:
        raise RuntimeError('Reviewed annotation callable changed: constants') from error
    # @wraps changes function.__qualname__ for safe wrappers. Their actual
    # compiled code is unique; ordinary factory closures retain lexical names.
    named = [pair for pair in matches if pair[0]['qualname'] == function.__qualname__]
    if len(named) == 1:
        matches = named
    if len(matches) != 1:
        raise RuntimeError('Reviewed annotation callable changed: executing code (' + relative + ':' + function.__qualname__ + ')')
    record, compiled = matches[0]
    return relative, record


def _function(function):
    """Describe the actual executing function, including all closure bindings.

    inspect.getsource(function) unwraps @wraps and hides register.safe; inspect
    its code object for wrapper proof, and record unwrapped proofs separately.
    """
    if not isinstance(function, types.FunctionType):
        raise RuntimeError('Unreviewed annotation callable')
    path, definition = _trusted_definition(function)
    closure = {}
    for name, cell in zip(function.__code__.co_freevars, function.__closure__ or ()):
        value = cell.cell_contents
        closure[name] = {'function': _function(value)} if isinstance(value, types.FunctionType) else {'value': _constant(value)}
    return {'path': path, 'qualname': definition['qualname'],
        'globals_module': function.__globals__.get('__name__'),
        'source_sha256': definition['source_sha256'], 'ast_sha256': definition['ast_sha256'], 'closure': closure}


def _bindings(function):
    return dict(zip(function.__code__.co_freevars, (c.cell_contents for c in function.__closure__ or ())))


def _layers(check):
    safe = check.evaluate; values = _bindings(safe)
    if (set(values) != {'checked', 'id', 'kind', 'provider', 'target'}
            or any(values[k] != getattr(check, k) for k in ('id', 'kind', 'provider', 'target'))):
        raise RuntimeError('Annotation registry wrapper binding changed')
    checked = values['checked']; guard = _bindings(checked)
    if set(guard) != {'function'}:
        raise RuntimeError('Annotation checked wrapper changed')
    native_guard = guard['function']; native = _bindings(native_guard)
    if set(native) != {'function'} or getattr(safe, '__wrapped__', None) is not native_guard:
        raise RuntimeError('Annotation native-field wrapper changed')
    return safe, checked, native_guard, native['function']


def _metadata(check):
    # Preserve exact title/remediation too, without editing canonical copy here.
    return {key: getattr(check, key) for key in ('id', 'provider', 'category', 'kind', 'title',
        'severity', 'control', 'remediation', 'target', 'allow_incomplete_failure')} | {
        'declared_dependencies': list(check.declared_dependencies),
        'dependencies': list(check.dependencies),
        'empty_applicability_dependencies': list(check.empty_applicability_dependencies)}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError('Duplicate annotation admission field')
        result[key] = value
    return result


def _inputs_unchecked():
    from . import k8s_annotation_indicators_review_20261020 as candidate
    root = Path(__file__).resolve().parents[2]
    receipt = _source_receipt()
    required = {'schema_version', 'ids', 'python_bytecode', 'sources', 'callables', 'schema',
        'predecessors', 'fixtures', 'historical_case_sha256', 'compiled_sources', 'lineage'}
    if (set(receipt) != required or receipt['schema_version'] != 2 or receipt['ids'] != list(IDS)
            or tuple(candidate.IDS) != IDS or set(receipt['predecessors']) != set(IDS)
            or set(receipt['historical_case_sha256']) != set(IDS)):
        raise RuntimeError('Unrecognized annotation admission receipt')
    if receipt['python_bytecode'] != 'compare_to_trusted_source_compiled_on_current_interpreter':
        raise RuntimeError('Unrecognized annotation admission receipt comparison')
    legacy = Path(__file__).with_suffix('.json')
    if _hash(legacy.read_text()) != receipt['lineage']['predecessor_receipt_sha256']:
        raise RuntimeError('Historical annotation admission receipt changed')
    if not isinstance(receipt['compiled_sources'], dict) or not receipt['compiled_sources']:
        raise RuntimeError('Malformed annotation compiled source receipt')
    if (not isinstance(receipt['sources'], list) or len(receipt['sources']) != len(SOURCE_PATHS)
            or {r['path'] for r in receipt['sources']} != set(SOURCE_PATHS)
            or set(receipt['schema']) != set(SCHEMA_KEYS)
            or not isinstance(receipt['callables'], list)
            or len(receipt['callables']) != sum(len(v) for v in CALLABLES.values())
            or {(r['module'], r['symbol']) for r in receipt['callables']} !=
               {(m, n) for m, names in CALLABLES.items() for n in names}):
        raise RuntimeError('Malformed annotation source receipt')
    for entry in receipt['sources']:
        path = (root / entry['path']).resolve()
        try:
            valid = (set(entry) == {'path', 'sha256'} and path.is_relative_to(root)
                and _hash(_verified_source(entry['path'], path.read_bytes(), receipt['compiled_sources'].get(entry['path']))) == entry['sha256'])
        except RuntimeError:
            raise RuntimeError('Reviewed annotation source changed') from None
        if not valid:
            raise RuntimeError('Reviewed annotation source changed')
    for entry in receipt['callables']:
        if set(entry) != {'module', 'symbol', 'proof'}:
            raise RuntimeError('Malformed annotation callable receipt')
        module = importlib.import_module(entry['module'])
        function = module
        for part in entry['symbol'].split('.'):
            function = getattr(function, part)
        if _function(function) != entry['proof']:
            raise RuntimeError('Reviewed annotation producer or helper callable changed')
    from peaso.collectors import k8s_annotation_indicators_20261020 as producer
    schema = {name: getattr(producer, name) for name in receipt['schema']}
    if json.loads(json.dumps(schema)) != receipt['schema']:
        raise RuntimeError('Reviewed annotation indicator schema changed')
    fixture = receipt['fixtures']; path = (root / fixture['path']).resolve()
    if (set(fixture) != {'path', 'sha256'} or not path.is_relative_to(Path(__file__).parent)
            or _hash(path.read_bytes()) != fixture['sha256']):
        raise RuntimeError('Reviewed native annotation fixtures changed')
    cases = json.loads(path.read_text(), object_pairs_hook=_pairs)
    expected = {'pass', 'pass_index', 'fail', 'fail_index', 'unknown', 'unknown_index'}
    if set(cases) != set(IDS) or any(set(row) != expected for row in cases.values()):
        raise RuntimeError('Native annotation fixtures incomplete')
    return receipt, cases


def _reviewed_inputs():
    try:
        return _inputs_unchecked()
    except RuntimeError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OSError, IndexError):
        raise RuntimeError('Malformed native annotation admission receipt') from None


def _cell(value):
    return (lambda: value).__closure__[0]


def _clone(function, leaf, successor, memo):
    if function is leaf:
        return successor
    if function in memo:
        return memo[function]
    values = []
    for cell in function.__closure__ or ():
        value = cell.cell_contents
        values.append(_clone(value, leaf, successor, memo) if isinstance(value, types.FunctionType) else value)
    clone = types.FunctionType(function.__code__, function.__globals__, function.__name__,
        function.__defaults__, tuple(_cell(v) for v in values) if function.__closure__ else None)
    memo[function] = clone
    clone.__kwdefaults__ = deepcopy(function.__kwdefaults__)
    clone.__annotations__ = dict(function.__annotations__)
    clone.__module__, clone.__qualname__, clone.__doc__ = function.__module__, function.__qualname__, function.__doc__
    clone.__dict__.update(function.__dict__)
    if hasattr(function, '__wrapped__'):
        wrapped = function.__wrapped__
        if wrapped not in memo:
            raise RuntimeError('Annotation wrapper lineage is not shared with execution')
        clone.__wrapped__ = memo[wrapped]
    return clone


def _successor(check, candidate):
    leaf = _layers(check)[-1]
    evaluate = _clone(check.evaluate, leaf, candidate.evaluate_for(check.id), {})
    setattr(evaluate, MARK, check.id)
    return replace(check, evaluate=evaluate)


def _verify_successor(check, receipt, candidate):
    safe, checked, native_guard, leaf = _layers(check)
    if (getattr(safe, MARK, None) != check.id or _metadata(check) != receipt['predecessors'][check.id]['metadata']
            or _function(leaf) != _function(candidate.evaluate_for(check.id))
            or _bindings(leaf) != {'check_id': check.id}):
        raise RuntimeError('Annotation successor closure or metadata changed')
    expected = receipt['predecessors'][check.id]['function']
    actual = _function(safe)
    # Validate all original wrapper source/code/closure values, changing only
    # the old innermost predicate descriptor to this exact fresh factory leaf.
    expected = deepcopy(expected)
    expected['closure']['checked']['function']['closure']['function']['function']['closure']['function']['function'] = _function(leaf)
    if actual != expected:
        raise RuntimeError('Annotation successor wrappers changed')


def install():
    """Validate all five, preflight native witnesses, then commit atomically."""
    from . import CHECKS
    from .fixtures import CASES
    from . import k8s_annotation_indicators_review_20261020 as candidate
    receipt, cases = _reviewed_inputs()
    before = tuple(CHECKS); originals = dict(_PREDECESSORS)
    selected = {}
    for cid in IDS:
        matches = [c for c in CHECKS if c.id == cid]
        if len(matches) != 1:
            raise RuntimeError('Annotation predecessor absent or duplicated')
        check = matches[0]; selected[cid] = check
        if _hash(json.dumps(CASES[cid], sort_keys=True)) != receipt['historical_case_sha256'][cid]:
            raise RuntimeError('Historical annotation CASES changed')
        if getattr(check.evaluate, MARK, None) is not None:
            _verify_successor(check, receipt, candidate)
        else:
            try:
                if (_metadata(check) != receipt['predecessors'][cid]['metadata']
                        or _function(check.evaluate) != receipt['predecessors'][cid]['function']):
                    raise RuntimeError('Reviewed annotation predecessor changed')
            except RuntimeError:
                raise RuntimeError('Reviewed annotation predecessor changed') from None
    try:
        updates = {}
        for cid, check in selected.items():
            if getattr(check.evaluate, MARK, None) is not None:
                continue
            successor = _successor(check, candidate)
            _verify_successor(successor, receipt, candidate)
            for tag, expected in (('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')):
                if successor.evaluate(deepcopy(cases[cid][tag]), deepcopy(cases[cid][tag + '_index']))[0] != expected:
                    raise RuntimeError('Native annotation admission witness failed')
            updates[cid] = successor
        CHECKS[:] = [updates.get(c.id, c) for c in CHECKS]
        _PREDECESSORS.update({cid: old for cid, old in selected.items() if cid in updates})
    except Exception:
        CHECKS[:] = before
        _PREDECESSORS.clear(); _PREDECESSORS.update(originals)
        raise
