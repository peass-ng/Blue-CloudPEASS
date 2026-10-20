"""Atomic source/native-case admission for one optional bounded K8s log check."""
from copy import deepcopy
import contextlib
import hashlib
import inspect
import json
from pathlib import Path
import sys
import types

from . import k8s_annotation_native_admission_20261020 as proof
from . import k8s_selected_log_sample_secret_review_20261020 as candidate
from peaso.collectors import k8s_selected_log_sample_secret_indicators as producer

RECEIPT = 'k8s_selected_log_sample_admission_20261020.json'
CASES_FILE = 'k8s_selected_log_sample_admitted_cases_20261020.json'
MARK = '_k8s_selected_log_sample_admission_20261020'
CHECK = producer.CHECK


def _hash(raw):
    return hashlib.sha256(raw if isinstance(raw, bytes) else raw.encode()).hexdigest()


def _metadata(check):
    return {key: getattr(check, key) for key in ('id', 'provider', 'category', 'kind', 'title', 'severity',
        'control', 'remediation', 'target', 'allow_incomplete_failure')} | {
        'declared_dependencies': list(check.declared_dependencies),
        'empty_applicability_dependencies': list(check.empty_applicability_dependencies)}


def _schema():
    return {'producer': {key: getattr(producer, key) for key in ('KIND', 'CHECK', 'OPTION', 'MARKER', 'SCHEMA',
        'MAX_LOG', 'MAX_POD', 'MAX_TOTAL', 'MAX_SECONDS', 'MAX_CALLS', 'TAIL_LINES', 'WINDOW_SECONDS',
        'MAX_LEAKS', 'MAX_LOCATIONS')}, 'declarations': candidate.DECLARATIONS}


def _execution(function, records, expected=None):
    if not isinstance(function, types.FunctionType):
        raise RuntimeError('K8s log executing callable changed')
    module = sys.modules.get(function.__module__)
    if module is None or function.__globals__ is not vars(module):
        raise RuntimeError('K8s log callable globals changed')
    shape = lambda code: json.dumps(proof._code(code), sort_keys=True, allow_nan=False)
    matches = [(record, code) for record, code in records
        if code.co_name == function.__code__.co_name and shape(code) == shape(function.__code__)]
    named = [row for row in matches if row[0]['qualname'] == function.__qualname__]
    if len(named) == 1:
        matches = named
    if len(matches) != 1:
        raise RuntimeError('K8s log executing code changed')
    if expected is not None and matches[0][0]['qualname'] != expected:
        raise RuntimeError('K8s log callable binding changed')
    # The producer's @wraps wrapper and @contextmanager retain their actual
    # function closures. Compare those functions too, including wrapped bodies.
    for value in proof._bindings(function).values():
        if isinstance(value, types.FunctionType) and value.__module__ == module.__name__:
            _execution(value, records)


def reviewed_inputs():
    root = Path(__file__).resolve().parents[2]
    try:
        receipt = json.loads(Path(__file__).with_name(RECEIPT).read_text(), object_pairs_hook=proof._pairs)
        if (set(receipt) != {'schema_version', 'id', 'sources', 'shared_functions', 'fixtures', 'schema', 'metadata'}
                or receipt['schema_version'] != 1 or receipt['id'] != CHECK):
            raise RuntimeError('Malformed K8s log admission receipt')
        modules = (producer, candidate, sys.modules[__name__])
        expected_paths = {str(Path(m.__file__).resolve().relative_to(root)) for m in modules}
        if set(receipt['sources']) != expected_paths:
            raise RuntimeError('K8s log source set changed')
        compiled = {}
        for relative, expected in receipt['sources'].items():
            path = (root / relative).resolve()
            if not path.is_relative_to(root) or _hash(path.read_bytes()) != expected:
                raise RuntimeError('K8s log source changed')
            compiled[relative] = proof._compiled_source(path.read_bytes(), str(path), sys.flags.optimize)
        for module in (producer, candidate):
            records = compiled[str(Path(module.__file__).resolve().relative_to(root))]
            names = {record['qualname'] for record, _ in records if '.' not in record['qualname']}
            for name in names:
                value = vars(module).get(name)
                if not isinstance(value, types.FunctionType) or value.__module__ != module.__name__:
                    raise RuntimeError('K8s log callable binding changed')
                native = inspect.unwrap(value)
                if native.__globals__ is not vars(module):
                    raise RuntimeError('K8s log callable binding changed')
                _execution(native, records, expected=name)
                if value.__globals__ is vars(module) and value is not native:
                    if proof._bindings(value) != {'function': native}:
                        raise RuntimeError('K8s log callable binding changed')
                    _execution(value, records)
                elif value is not native:
                    template = contextlib.contextmanager(lambda: None)
                    if (value.__globals__ is not vars(contextlib) or value.__code__ is not template.__code__
                            or proof._bindings(value) != {'func': native}):
                        raise RuntimeError('K8s log context wrapper changed')
        if json.loads(json.dumps(_schema())) != receipt['schema']:
            raise RuntimeError('K8s log schema changed')
        from peaso.collectors import k8s
        shared = {'pool_init': k8s._BoundedPool.__init__, 'pool_request': k8s._BoundedPool.request}
        if set(receipt['shared_functions']) != set(shared):
            raise RuntimeError('K8s log shared source set changed')
        for name, function in shared.items():
            source = inspect.getsource(function)
            if _hash(source) != receipt['shared_functions'][name]:
                raise RuntimeError('K8s log transport source changed')
            # Compile the verified class source without executing it and check
            # the loaded method; no whole shared-module freeze is introduced.
            text = 'from __future__ import annotations\n' + inspect.getsource(k8s._BoundedPool)
            records = proof._compiled_source(text.encode(), str(Path(k8s.__file__)), sys.flags.optimize)
            _execution(function, records)
        proof._reviewed_inputs()  # Exact collect/register/native ancestors.
        expected_fixtures = {CASES_FILE, 'k8s_selected_log_sample_secret_review_20261020_native_fixtures.json',
            'k8s_selected_log_sample_secret_review_20261020_proposal.json'}
        if set(receipt['fixtures']) != expected_fixtures:
            raise RuntimeError('K8s log fixture set changed')
        for name, expected in receipt['fixtures'].items():
            if _hash(Path(__file__).with_name(name).read_bytes()) != expected:
                raise RuntimeError('K8s log native fixtures changed')
        cases = json.loads(Path(__file__).with_name(CASES_FILE).read_text(), object_pairs_hook=proof._pairs)
        if set(cases) != {CHECK} or set(cases[CHECK]) != {'pass', 'pass_index', 'fail', 'fail_index',
                'unknown', 'unknown_index', 'missing', 'malformed', 'index'}:
            raise RuntimeError('K8s log native cases incomplete')
        for branch in ('pass', 'fail', 'unknown'):
            if candidate.evaluate(deepcopy(cases[CHECK][branch]), deepcopy(cases[CHECK][branch + '_index']))[0] != branch.upper():
                raise RuntimeError('K8s log native witness changed')
        return receipt, cases, compiled
    except RuntimeError:
        raise
    except (ValueError, TypeError, KeyError, OSError, AttributeError, IndexError):
        raise RuntimeError('Malformed K8s log admission') from None


def _verify(check, receipt, compiled):
    if _metadata(check) != receipt['metadata'] or getattr(check.evaluate, MARK, None) != CHECK:
        raise RuntimeError('K8s log registered metadata changed')
    safe = check.evaluate
    bindings = proof._bindings(safe)
    if (set(bindings) != {'checked', 'id', 'kind', 'provider', 'target'}
            or any(bindings[key] != getattr(check, key) for key in ('id', 'kind', 'provider', 'target'))):
        raise RuntimeError('K8s log safe wrapper changed')
    checked = bindings['checked']
    inner = proof._bindings(checked)
    if set(inner) != {'function'} or inner['function'] is not candidate.evaluate or safe.__wrapped__ is not candidate.evaluate:
        raise RuntimeError('K8s log checked wrapper changed')
    proof._trusted_definition(safe)
    proof._trusted_definition(checked)
    relative = str(Path(candidate.__file__).resolve().relative_to(Path(__file__).resolve().parents[2]))
    _execution(inner['function'], compiled[relative])


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    from peaso.collectors import k8s
    receipt, cases, compiled = reviewed_inputs()
    if k8s.TYPES.count(producer.KIND) != 1 or producer.KIND in k8s.ENDPOINTS:
        raise RuntimeError('K8s log dedicated kind changed')
    found = [check for check in CHECKS if check.id == CHECK]
    if len(found) > 1:
        raise RuntimeError('K8s log registration collision')
    if found:
        _verify(found[0], receipt, compiled)
        if CASES.get(CHECK) != cases[CHECK]:
            raise RuntimeError('K8s log registered cases changed')
        return
    if CHECK in CASES:
        raise RuntimeError('K8s log cases collision')
    before = tuple(CHECKS)
    try:
        spec = candidate.DECLARATIONS[0]
        register(CHECK, 'k8s', spec['category'], producer.KIND, spec['title'], spec['severity'], spec['control'],
            spec['remediation'], dependencies=[producer.KIND], allow_incomplete_failure=True)(candidate.evaluate)
        setattr(CHECKS[-1].evaluate, MARK, CHECK)
        _verify(CHECKS[-1], receipt, compiled)
        CASES[CHECK] = deepcopy(cases[CHECK])
    except Exception:
        CHECKS[:] = before
        CASES.pop(CHECK, None)
        raise
